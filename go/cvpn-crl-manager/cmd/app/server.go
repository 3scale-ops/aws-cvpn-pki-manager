package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/vault"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
)

// serverOptions is the options for the command
type serverOptions struct {
	port                string
	clientVPNEndpointID string
	vaultPKIPaths       []string
	vaultClientCrtRole  string
	vaultKVPath         string
	CfgTplPath          string
}

var serverOpts serverOptions

// serverCmd represents the validating-webhook command
var serverCmd = &cobra.Command{
	Use:     "server",
	Short:   "Starts a server that will listen for http requests",
	Long:    "",
	Example: "cvpn-crl-manager server --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX",
	Run:     runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVar(&serverOpts.port, "port", "8080", "Port to listen at")
	serverCmd.Flags().StringVar(&serverOpts.clientVPNEndpointID, "client-vpn-endpoint-id", "", "The AWS Client VPN endpoint ID")
	serverCmd.MarkFlagRequired("client-vpn-endpoint-id")
	serverCmd.Flags().StringSliceVar(&serverOpts.vaultPKIPaths, "vault-pki-paths", []string{"cvpn-pki", "root-pki"}, "The paths where the root CA and any intermediate CAs live in Vault")
	serverCmd.Flags().StringVar(&serverOpts.vaultClientCrtRole, "vault-client-certificate-role", "client", "The Vault role used to issue VPN client certificates")
	serverCmd.Flags().StringVar(&serverOpts.vaultKVPath, "vault-kv-store-path", "secret", "The Vault path for the kv (v2) storage engine where VPN configs will be stored")
	serverCmd.Flags().StringVar(&serverOpts.CfgTplPath, "config-template-path", "./config.ovpn.tpl", "The OpenVPN config template")
}

func runServer(cmd *cobra.Command, args []string) {

	// Create a single shared cient to talk to the
	// Vault server
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		panic(err)
	}

	// Use gorilla/mux as http router
	mux := mux.NewRouter()
	mux.HandleFunc("/crl", getCRLHandler(client)).Methods(http.MethodGet)
	mux.HandleFunc("/crl", updateCRLHandler(client)).Methods(http.MethodPost)
	mux.HandleFunc("/issue/{user}", issueClientCertificateHandler(client)).Methods(http.MethodPost)
	mux.HandleFunc("/revoke/{user}", revokeUserHandler(client)).Methods(http.MethodPost)
	mux.HandleFunc("/users", listUsersHandler(client)).Methods(http.MethodGet)
	// Add a logging middleware
	loggedRouter := handlers.CombinedLoggingHandler(os.Stdout, mux)

	// Start the server
	log.Print("Started server")
	log.Printf("Listening on port :%v", serverOpts.port)
	log.Fatal(http.ListenAndServe(":"+serverOpts.port, loggedRouter))
}

func issueClientCertificateHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		err := operations.IssueClientCertificate(
			&operations.IssueCertificateRequest{
				Client:              client,
				VaultPKIPaths:       serverOpts.vaultPKIPaths,
				PKIRole:             serverOpts.vaultClientCrtRole,
				Username:            vars["user"],
				ClientVPNEndpointID: serverOpts.clientVPNEndpointID,
				VaultKVPath:         serverOpts.vaultKVPath,
				CfgTplPath:          serverOpts.CfgTplPath,
			})
		if err != nil {
			http.Error(w, jsonOutput(map[string]string{"error": "couldn't revoke user " + vars["user"] + ":\n" + err.Error()}), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, jsonOutput(map[string]string{"result": "success"}))
	}
}

func revokeUserHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		err := operations.RevokeUser(
			&operations.RevokeUserRequest{
				Client:              client,
				PKIPath:             serverOpts.vaultPKIPaths[0],
				Username:            vars["user"],
				ClientVPNEndpointID: serverOpts.clientVPNEndpointID,
			})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, jsonOutput(map[string]string{"error": "internal error, couldn't revoke user " + vars["user"] + ":\n" + err.Error()}), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, jsonOutput(map[string]string{"result": "success"}))
	}
}

func getCRLHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		crl, err := operations.GetCRL(
			&operations.GetCRLRequest{
				Client:  client,
				PKIPath: serverOpts.vaultPKIPaths[0],
			})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, jsonOutput(map[string]string{"error": "internal error, coult'n retrieve the CRL:\n" + err.Error()}), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, jsonOutput(map[string]string{"crl": string(crl)}))
	}
}

func updateCRLHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Update the crl
		crl, err := operations.UpdateCRL(
			&operations.UpdateCRLRequest{
				Client:              client,
				PKIPath:             serverOpts.vaultPKIPaths[0],
				ClientVPNEndpointID: serverOpts.clientVPNEndpointID,
			})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, jsonOutput(map[string]string{"error": "internal error, CRL could not be updated:\n" + err.Error()}), http.StatusInternalServerError)

			return
		}

		fmt.Fprintln(w, string(crl))
	}
}

func listUsersHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := operations.ListUsers(
			&operations.ListUsersRequest{
				Client:  client,
				PKIPath: serverOpts.vaultPKIPaths[0],
			})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, jsonOutput(map[string]string{"error": "internal error, could not retrieve the user list:\n" + err.Error()}), http.StatusInternalServerError)
			return
		}
		b, err := json.MarshalIndent(users, "", "  ")
		fmt.Fprintln(w, string(b))
	}
}

func jsonOutput(rsp map[string]string) string {
	b, err := json.MarshalIndent(rsp, "", "  ")
	if err != nil {
		log.Panic("Error marhsalling the response json")
	}
	return string(b)
}
