package operations

import (
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
)

// GetCRL return the Client Revocation List PEM as a []byte
func GetCRL(client *api.Client, pki string) ([]byte, error) {
	req := client.NewRequest("GET", fmt.Sprintf("/v1/%s/crl/pem", pki))
	rsp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	return data, nil
}
