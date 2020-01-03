package operations

import (
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
)

// UpdateCRL maintains the CRL to keep just one active certificte per
// VPN user. This will always be the one emitted at a later date. Users
// can also have all their certificates revoked.
func UpdateCRL(client *api.Client, pki string) error {

	// Get the list of users
	users, err := ListUsers(client, pki)
	if err != nil {
		return err
	}

	//For each user, get the list of certificates, and revoke all of the but the latest
	for _, crts := range users {
		err := revokeUserCertificates(client, pki, crts, false)
		if err != nil {
			return err
		}
	}

	return nil
}

// revokeUserCertificates receives a list of certificates, sorted from oldest to newest, and revokes
// all but the latest if "revokeAll" is false and all of them if "revokeAll" is true.
func revokeUserCertificates(client *api.Client, pki string, crts []Certificate, revokeAll bool) error {

	for n, crt := range crts {
		// Do not revoke the last certificate
		if n == len(crts)-1 && revokeAll == false {
			break
		}
		if crt.Revoked == false {
			payload := make(map[string]interface{})
			payload["serial_number"] = crt.SerialNumber
			log.Printf("Revoke cert %s\n", crt.SerialNumber)
			client.Logical().Write(fmt.Sprintf("%s/revoke", pki), payload)
		}
	}

	return nil
}
