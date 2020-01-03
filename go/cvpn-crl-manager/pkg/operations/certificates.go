package operations

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

// IssueClientCertificate generates a new certificate for a given users, causing
// the revocation of other certificates emitted for that same user
func IssueClientCertificate(client *api.Client, pki string, username string, pkiRole string) error {
	// Issue a new certificate
	payload := make(map[string]interface{})
	payload["common_name"] = username
	_, err := client.Logical().Write(fmt.Sprintf("%s/issue/%s", pki, pkiRole), payload)
	if err != nil {
		return err
	}

	// TODO: Update the OpenVPN config file in secret/data/users/<username>/
	// This will be the only place where the private key will be stored as
	// Vault does not store the private key when generating a certificate

	// Code to load the vpn config file template from a file
	// ...

	// Code to generate the config file from the template file
	// ...

	// Code to create/update the vpn config in the kv store
	// ...

	// Call UpdateCRL to revoke all other certificates
	_, err = UpdateCRL(client, pki)
	if err != nil {
		return err
	}

	return nil
}
