package operations

import (
	"fmt"
	"io/ioutil"

	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/vault"
)

// GetCRL return the Client Revocation List PEM as a []byte
func GetCRL(vaultAddr string, vaultToken string, pki string) ([]byte, error) {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	req := client.NewRequest("GET", fmt.Sprintf("/v1/%s/crl/pem", pki))
	rsp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	return data, nil
}
