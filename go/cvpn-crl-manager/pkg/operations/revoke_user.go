package operations

import "github.com/hashicorp/vault/api"

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
