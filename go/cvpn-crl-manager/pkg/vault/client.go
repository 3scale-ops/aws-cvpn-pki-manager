package vault

import (
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a new authenticated client to
// interact with a vault server's API
func NewClient(vaultAddr string, vaultToken string) (*api.Client, error) {

	// vaultTokenFromEnv := token

	// if vaultTokenFromEnv != "" {
	// 	vaultToken = vaultTokenFromEnv
	// } else {
	// 	vaultTokenFromCache, err := ioutil.ReadFile(fmt.Sprintf("%s/.vault-token", os.Getenv("HOME")))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	vaultToken = string(vaultTokenFromCache)
	// }

	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	client, err := api.NewClient(&api.Config{Address: vaultAddr, HttpClient: httpClient})
	if err != nil {
		return nil, err
	}
	client.SetToken(vaultToken)

	return client, nil
}
