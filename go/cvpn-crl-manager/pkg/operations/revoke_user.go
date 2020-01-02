package operations

import (
	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/vault"
)

// RevokeUser revokes all the issued certificates for a given user
func RevokeUser(vaultAddr string, vaultToken string, pki string, username string) error {

	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return err
	}

	// Get the list of users
	users, err := ListUsers(vaultAddr, vaultToken, pki)
	err = revokeUserCertificates(client, pki, users[username], true)
	if err != nil {
		return err
	}

	return nil
}
