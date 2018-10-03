/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"crypto/x509"
	"io/ioutil"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// LocalRegister is used to generate host keys when a node or proxy is running within the same process
// as the auth server. This method does not need to use provisioning tokens.
func LocalRegister(id IdentityID, authServer *AuthServer, additionalPrincipals []string) (*Identity, error) {
	keys, err := authServer.GenerateServerKeys(GenerateServerKeysRequest{
		HostID:               id.HostUUID,
		NodeName:             id.NodeName,
		Roles:                teleport.Roles{id.Role},
		AdditionalPrincipals: additionalPrincipals,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ReadIdentityFromKeyPair(keys.Key, keys.Cert, keys.TLSCert, keys.TLSCACerts)
}

// RegisterParams specifies parameters
// for first time register operation with auth server
type RegisterParams struct {
	// DataDir is the data directory
	// storing CA certificate
	DataDir string
	// Token is a secure token to join the cluster
	Token string
	// ID is identity ID
	ID IdentityID
	// Servers is a list of auth servers to dial
	Servers []utils.NetAddr
	// AdditionalPrincipals is a list of additional principals to dial
	AdditionalPrincipals []string
	// PrivateKey is a PEM encoded private key (not passed to auth servers)
	PrivateKey []byte
	// PublicTLSKey is a server's public key to sign
	PublicTLSKey []byte
	// PublicSSHKey is a server's public SSH key to sign
	PublicSSHKey []byte
	// CipherSuites is a list of cipher suites to use for TLS client connection
	CipherSuites []uint16

	// CAPath is the path to the CA used to verify the TLS connection to the
	// Auth Server.
	CAPath string

	// CAPin is the SKPI hash of the CA used to verify the Auth Server.
	CAPin string

	// InsecureSkipCAVerification skips checking the CA when establishing a
	// connection the Auth Server.
	InsecureSkipCAVerification bool
}

// Register is used to generate host keys when a node or proxy are running on
// different hosts than the auth server. This method requires provisioning
// tokens to prove a valid auth server was used to issue the joining request
// as well as a method for the node to validate the auth server.
func Register(params RegisterParams) (*Identity, error) {
	// Read in the token. The token can either be passed in or come from a file
	// on disk.
	tok, err := readToken(params.Token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build a client to the Auth Server. The client can either not verify the
	// Auth Server, use a CA pin to verify the Auth Server, or a CA certificate.
	var client *Client
	switch {
	case params.InsecureSkipCAVerification:
		client, err = insecureRegisterClient(params)
	case params.CAPin != "":
		client, err = pinRegisterClient(params)
	case params.CAPath != "":
		client, err = pathRegisterClient(params)
	default:
		return nil, trace.BadParameter("to register node, either CA pin, CA path, " +
			"or insecure configuration is required")
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer client.Close()

	// Get the SSH and X509 certificates for a node.
	keys, err := client.RegisterUsingToken(RegisterUsingTokenRequest{
		Token:                tok,
		HostID:               params.ID.HostUUID,
		NodeName:             params.ID.NodeName,
		Role:                 params.ID.Role,
		AdditionalPrincipals: params.AdditionalPrincipals,
		PublicTLSKey:         params.PublicTLSKey,
		PublicSSHKey:         params.PublicSSHKey,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ReadIdentityFromKeyPair(
		params.PrivateKey, keys.Cert, keys.TLSCert, keys.TLSCACerts)
}

// insecureRegisterClient connects to the Auth Server regardless of the
// certificate it presents.
func insecureRegisterClient(params RegisterParams) (*Client, error) {
	log.Warnf("Joining remote cluster with insecure CA configuration to Auth Server. " +
		"This may open you up to a Man-In-The-Middle (MITM) attack if an attacker " +
		"has privileged network access. Proceed with caution.")

	tlsConfig := utils.TLSConfig(params.CipherSuites)
	tlsConfig.InsecureSkipVerify = true

	client, err := NewTLSClient(params.Servers, tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client, nil
}

// pinRegisterClient first connects to the Auth Server using a insecure
// connection to fetch the root CA. If the root CA matches the provided CA
// pin, a connection will be re-established and the root CA will be used to
// validate the certificate presented. If both conditions hold true, then we
// know we are connecting to the expected Auth Server.
func pinRegisterClient(params RegisterParams) (*Client, error) {
	// Build a insecure client to the Auth Server. This is safe because even if
	// an attacker were to MITM this connection the CA pin will not match below.
	tlsConfig := utils.TLSConfig(params.CipherSuites)
	tlsConfig.InsecureSkipVerify = true
	client, err := NewTLSClient(params.Servers, tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer client.Close()

	// Fetch the root CA from the Auth Server. The NOP role has access to the
	// GetLocalCA endpoint.
	localCA, err := client.GetLocalCA()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsCA, err := tlsca.ParseCertificatePEM(localCA.TLSCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check that the SKPI pin matches the CA we fetched over a insecure
	// connection. This makes sure the CA fetched over a insecure connection is
	// in-fact the expected CA.
	err = utils.CheckSKPI(params.CAPin, tlsCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.Infof("Joining remote cluster %v with CA pin.", tlsCA.Subject.CommonName)

	// Create another client, but this time with the CA provided to validate
	// that the Auth Server was issued a certificate by the same CA.
	tlsConfig = utils.TLSConfig(params.CipherSuites)
	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCA)
	tlsConfig.RootCAs = certPool

	client, err = NewTLSClient(params.Servers, tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client, nil
}

// pathRegisterClient validates the connection to the Auth Server using a
// certificate on disk.
func pathRegisterClient(params RegisterParams) (*Client, error) {
	// Read in the CA that will be used to validate the certificate that the
	// Auth Server presents.
	certBytes, err := utils.ReadPath(params.CAPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := tlsca.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse certificate at %v", params.CAPath)
	}

	log.Infof("Joining remote cluster %v with CA file.", cert.Subject.CommonName)

	tlsConfig := utils.TLSConfig(params.CipherSuites)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	tlsConfig.RootCAs = certPool

	client, err := NewTLSClient(params.Servers, tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client, nil
}

// ReRegisterParams specifies parameters for re-registering
// in the cluster (rotating certificates for existing members)
type ReRegisterParams struct {
	// Client is an authenticated client using old credentials
	Client ClientI
	// ID is identity ID
	ID IdentityID
	// AdditionalPrincipals is a list of additional principals to dial
	AdditionalPrincipals []string
	// PrivateKey is a PEM encoded private key (not passed to auth servers)
	PrivateKey []byte
	// PublicTLSKey is a server's public key to sign
	PublicTLSKey []byte
	// PublicSSHKey is a server's public SSH key to sign
	PublicSSHKey []byte
}

// ReRegister renews the certificates and private keys based on the client's existing identity.
func ReRegister(params ReRegisterParams) (*Identity, error) {
	hostID, err := params.ID.HostID()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	keys, err := params.Client.GenerateServerKeys(GenerateServerKeysRequest{
		HostID:               hostID,
		NodeName:             params.ID.NodeName,
		Roles:                teleport.Roles{params.ID.Role},
		AdditionalPrincipals: params.AdditionalPrincipals,
		PublicTLSKey:         params.PublicTLSKey,
		PublicSSHKey:         params.PublicSSHKey,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ReadIdentityFromKeyPair(params.PrivateKey, keys.Cert, keys.TLSCert, keys.TLSCACerts)
}

func readToken(token string) (string, error) {
	if !strings.HasPrefix(token, "/") {
		return token, nil
	}
	// treat it as a file
	out, err := ioutil.ReadFile(token)
	if err != nil {
		return "", nil
	}
	// trim newlines as tokens in files tend to have newlines
	return strings.TrimSpace(string(out)), nil
}

// PackedKeys is a collection of private key, SSH host certificate
// and TLS certificate and certificate authority issued the certificate
type PackedKeys struct {
	// Key is a private key
	Key []byte `json:"key"`
	// Cert is an SSH host cert
	Cert []byte `json:"cert"`
	// TLSCert is an X509 certificate
	TLSCert []byte `json:"tls_cert"`
	// TLSCACerts is a list of certificate authorities
	TLSCACerts [][]byte `json:"tls_ca_certs"`
}
