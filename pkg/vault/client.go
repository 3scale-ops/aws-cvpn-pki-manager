package vault

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// AuthenticatedClient represents an authenticated
// client that can talk to the vault server
type AuthenticatedClient interface {
	GetClient() (*api.Client, error)
}

// TokenAuthenticatedClient is the config
// object required to create a token based authenticated
// Vault client
type TokenAuthenticatedClient struct {
	Address string
	Token   string
	client  *api.Client
	sync.Mutex
}

// GetClient creates a new authenticated client to
// interact with a vault server's API. A token is directly passed
// for authentication
// Does not implement token renewal
func (tac *TokenAuthenticatedClient) GetClient() (*api.Client, error) {

	if tac.client == nil {
		tac.Lock()
		defer tac.Unlock()
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return nil, err
		}
		client.SetAddress(tac.Address)
		client.SetToken(tac.Token)
		client.SetClientTimeout(10 * time.Second)
		tac.client = client
	}
	return tac.client, nil
}

// ApproleAuthenticatedClient is the config
// object required to create a Vault client that
// authenticates using Vault's Approle auth backend
type ApproleAuthenticatedClient struct {
	Address      string
	SecretID     string
	RoleID       string
	BackendPath  string
	client       *api.Client
	tokenExpires time.Time
	sync.Mutex
}

// GetClient uses the Approle auth backend to obtain a token
// Implements token renewal
// approleSecretID string, approleRoleID string,
func (aac *ApproleAuthenticatedClient) GetClient() (*api.Client, error) {

	// spew.Dump(aac.client.Token())
	// spew.Dump(aac.tokenExpires)

	// If token not empty and still valid (with a margin of 60 seconds)
	if aac.client != nil && aac.client.Token() != "" && time.Now().Add(60*time.Second).Before(aac.tokenExpires) {
		// the token, and therefor the client, are still valid for use
		return aac.client, nil
	}

	// either the client is still not created or the
	// token has expired ...
	aac.Lock()
	defer aac.Unlock()
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	client.SetAddress(aac.Address)
	client.SetClientTimeout(10 * time.Second)

	// request a new token using approle auth backend
	// with configured options
	payload := map[string]string{
		"role_id":   aac.RoleID,
		"secret_id": aac.SecretID,
	}
	req := client.NewRequest("POST", fmt.Sprintf("/v1/auth/%s/login", aac.BackendPath))
	req.SetJSONBody(payload)
	rsp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	err = rsp.DecodeJSON(&data)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	// Configure the client to use the token
	auth := data["auth"].(map[string]interface{})
	client.SetToken(auth["client_token"].(string))

	// Update the client in the shared object
	aac.client = client

	// Update the token expiration time in the shared object
	lease, err := time.ParseDuration(auth["lease_duration"].(json.Number).String() + "s")
	if err != nil {
		return nil, err
	}
	aac.tokenExpires = time.Now().Add(lease)

	return aac.client, nil
}
