package operations

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/api"
)

// IssueCertificateRequest is the structure containing
// the required data to issue a new certificate
type IssueCertificateRequest struct {
	Client              *api.Client
	PKIPath             string
	Username            string
	PKIRole             string
	ClientVPNEndpointID string
	KVPath              string
}

// IssueClientCertificate generates a new certificate for a given users, causing
// the revocation of other certificates emitted for that same user
func IssueClientCertificate(r *IssueCertificateRequest) error {
	// Issue a new certificate
	payload := make(map[string]interface{})
	payload["common_name"] = r.Username
	rsp, err := r.Client.Logical().Write(fmt.Sprintf("%s/issue/%s", r.PKIPath, r.PKIRole), payload)
	if err != nil {
		return err
	}

	spew.Dump(rsp.Data) // access fields with r.Data["certificate"]

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
	_, err = UpdateCRL(
		&UpdateCRLRequest{
			Client:              r.Client,
			PKIPath:             r.PKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})

	if err != nil {
		return err
	}

	return nil
}

func updateUserConfig(client *api.Client) error {

	return nil
}
