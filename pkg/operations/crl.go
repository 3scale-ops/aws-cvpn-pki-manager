package operations

import (
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/vault/api"
)

// GetCRLRequest is the structure containing
// the required data to issue a new certificate
type GetCRLRequest struct {
	Client       *api.Client
	VaultPKIPath string
}

// GetCRL return the Client Revocation List PEM as a []byte
func GetCRL(r *GetCRLRequest) ([]byte, error) {
	req := r.Client.NewRequest("GET", fmt.Sprintf("/v1/%s/crl/pem", r.VaultPKIPath))
	rsp, err := r.Client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	return data, nil
}

// UpdateCRLRequest is the structure containing
// the required data to issue a new certificate
type UpdateCRLRequest struct {
	Client              *api.Client
	VaultPKIPath        string
	ClientVPNEndpointID string
}

// UpdateCRL maintains the CRL to keep just one active certificte per
// VPN user. This will always be the one emitted at a later date. Users
// can also have all their certificates revoked.
func UpdateCRL(r *UpdateCRLRequest) ([]byte, error) {

	// Get the list of users
	users, err := ListUsers(
		&ListUsersRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})
	if err != nil {
		return nil, err
	}

	//For each user, get the list of certificates, and revoke all of the but the latest
	for _, crts := range users {
		err := revokeUserCertificates(r.Client, r.VaultPKIPath, crts, false)
		if err != nil {
			return nil, err
		}
	}

	// Get the updated CRL
	crl, err := GetCRL(
		&GetCRLRequest{
			Client:       r.Client,
			VaultPKIPath: r.VaultPKIPath,
		})

	// Upload new CRL to AWS Client VPN endpoint
	svc := ec2.New(session.New())

	_, err = svc.ImportClientVpnClientCertificateRevocationList(
		&ec2.ImportClientVpnClientCertificateRevocationListInput{
			CertificateRevocationList: aws.String(string(crl)),
			ClientVpnEndpointId:       aws.String(r.ClientVPNEndpointID),
		})

	if err != nil && err.(awserr.Error).Code() != "InvalidParameterValue" {
		return nil, err
	}

	return crl, nil
}
