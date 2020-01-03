package operations

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// ListUsers retrieves the list of all Client VPN users and certificates
func ListUsers(client *api.Client, pki string) (map[string][]Certificate, error) {
	users := map[string][]Certificate{}

	secret, err := client.Logical().List(fmt.Sprintf("%s/certs", pki))
	if err != nil {
		return nil, err
	}

	crl, err := GetCRL(client, pki)
	if err != nil {
		return nil, err
	}

	for _, key := range secret.Data["keys"].([]interface{}) {
		secret, err := client.Logical().Read(fmt.Sprintf("%s/cert/%s", pki, key))
		if err != nil {
			return nil, err
		}
		rawCert := secret.Data["certificate"].(string)
		block, _ := pem.Decode([]byte(rawCert))
		if block == nil {
			return nil, errors.Wrapf(err, "failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse certificate")
		}

		if cert.IsCA == true || isServerCertificate(cert) == true {
			// Do not list the CA
			continue
		}

		// TODO: get the system's timezone instead of hardcoding it
		jst := time.FixedZone("Europe/Madrid", 9*60*60)
		notBefore := cert.NotBefore.In(jst)
		notAfter := cert.NotAfter.In(jst)
		serial := strings.TrimSpace(getHexFormatted(cert.SerialNumber.Bytes(), "-"))
		revoked, err := isRevoked(serial, crl)
		if err != nil {
			return nil, err
		}

		username := strings.Split(cert.Subject.CommonName, "@")[0]
		users[username] = append(users[username], Certificate{
			serial,
			cert.Issuer.CommonName,
			cert.Subject.CommonName,
			notBefore,
			notAfter,
			revoked,
			rawCert,
		})
	}

	// Sort the arrays but notBefore date (which should be the
	// date the certificate was emitted at)
	for _, crts := range users {
		sort.Slice(crts, func(i, j int) bool {
			return crts[i].NotBefore.Before(crts[j].NotBefore)
		})
	}

	return users, nil
}

// RevokeUser revokes all the issued certificates for a given user
func RevokeUser(client *api.Client, pki string, username string) error {

	// Get the list of users
	users, err := ListUsers(client, pki)
	err = revokeUserCertificates(client, pki, users[username], true)
	if err != nil {
		return err
	}

	return nil
}

func getHexFormatted(buf []byte, sep string) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprintf(&ret, sep)
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

func isRevoked(serial string, crl []byte) (bool, error) {
	parsed, err := x509.ParseCRL(crl)
	if err != nil {
		return false, err
	}
	list := parsed.TBSCertList.RevokedCertificates
	for _, crt := range list {
		if serial == strings.TrimSpace(getHexFormatted(crt.SerialNumber.Bytes(), "-")) {
			return true, nil
		}
	}
	return false, nil
}

func isServerCertificate(cert *x509.Certificate) bool {
	flag := false
	for _, use := range cert.ExtKeyUsage {
		if use == x509.ExtKeyUsageServerAuth {
			flag = true
		}
	}
	return flag
}
