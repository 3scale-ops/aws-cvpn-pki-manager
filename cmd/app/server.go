package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/3scale/aws-cvpn-pki-manager/pkg/operations"
	"github.com/3scale/aws-cvpn-pki-manager/pkg/vault"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	Example: "aws-cvpn-pki-manager server --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX --client-vpn-endpoint-id cvpn-endpoint-0873f24b07b72b3ee",
	Run:     runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	cobra.OnInitialize(initConfig)

	serverCmd.Flags().StringVar(&serverOpts.port, "port", "", "Port to listen at")
	viper.BindPFlag("port", serverCmd.Flags().Lookup("port"))
	viper.SetDefault("port", "8080")

	serverCmd.Flags().StringVar(&serverOpts.clientVPNEndpointID, "client-vpn-endpoint-id", "", "The AWS Client VPN endpoint ID")
	viper.BindPFlag("client-vpn-endpoint-id", serverCmd.Flags().Lookup("client-vpn-endpoint-id"))

	serverCmd.Flags().StringSliceVar(&serverOpts.vaultPKIPaths, "vault-pki-paths", []string{}, "The paths where the root CA and any intermediate CAs live in Vault. Must be sorted, the rootCA PKI path has to be last one")
	viper.BindPFlag("vault-pki-paths", serverCmd.Flags().Lookup("vault-pki-paths"))
	viper.SetDefault("vault-pki-paths", []string{"cvpn-pki", "root-pki"})

	serverCmd.Flags().StringVar(&serverOpts.vaultClientCrtRole, "vault-client-certificate-role", "", "The Vault role used to issue VPN client certificates")
	viper.BindPFlag("vault-client-certificate-role", serverCmd.Flags().Lookup("vault-client-certificate-role"))
	viper.SetDefault("vault-client-certificate-role", "client")

	serverCmd.Flags().StringVar(&serverOpts.vaultKVPath, "vault-kv-path", "secret", "The Vault path for the kv (v2) storage engine where VPN configs will be stored")
	viper.BindPFlag("vault-kv-path", serverCmd.Flags().Lookup("vault-kv-path"))
	viper.SetDefault("vault-kv-path", "secret")

	serverCmd.Flags().StringVar(&serverOpts.CfgTplPath, "config-template-path", "./config.ovpn.tpl", "The OpenVPN config template")
	viper.BindPFlag("config-template-path", serverCmd.Flags().Lookup("config-template-path"))
	viper.SetDefault("config-template-path", "./config.ovpn.tpl")
}

func initConfig() {
	keys := []string{
		"port",
		"vault-addr",
		"vault-token",
		"client-vpn-endpoint-id",
		"vault-pki-paths",
		"vault-client-certificate-role",
		"vault-kv-path",
		"config-template-path",
	}

	for _, k := range keys {
		if !viper.IsSet(k) {
			log.Panicf("Required configuration option '%s' is not set", k)
		}
	}

	format := `Loaded config:
			vault-addr: %s
			vault-token: ****************
			client-vpn-endpoint-id: %s
			vault-pki-paths: %s
			vault-client-certificate-role: %s
			vault-kv-store-path: %s
			config-template-path: %s
	`

	log.Printf(format, viper.GetString("vault-addr"), viper.GetString("client-vpn-endpoint-id"),
		viper.GetStringSlice("vault-pki-paths"), viper.GetString("vault-client-certificate-role"),
		viper.GetString("vault-kv-path"), viper.GetString("config-template-path"))

}

func runServer(cmd *cobra.Command, args []string) {

	// Create a single shared cient to talk to the
	// Vault server
	client, err := vault.NewClient(viper.GetString("vault-addr"), viper.GetString("vault-token"))
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
	log.Printf("Listening on port :%v", viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), loggedRouter))
}

func issueClientCertificateHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		err := operations.IssueClientCertificate(
			&operations.IssueCertificateRequest{
				Client:              client,
				VaultPKIPaths:       viper.GetStringSlice("vault-pki-paths"),          //serverOpts.vaultPKIPaths,
				VaultPKIRole:        viper.GetString("vault-client-certificate-role"), //serverOpts.vaultClientCrtRole,
				Username:            vars["user"],
				ClientVPNEndpointID: viper.GetString("client-vpn-endpoint-id"), //serverOpts.clientVPNEndpointID,
				VaultKVPath:         viper.GetString("vault-kv-path"),          //serverOpts.vaultKVPath,
				CfgTplPath:          viper.GetString("config-template-path"),   //serverOpts.CfgTplPath,
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
				PKIPath:             viper.GetStringSlice("vault-pki-paths")[0],
				Username:            vars["user"],
				ClientVPNEndpointID: viper.GetString("client-vpn-endpoint-id"),
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
				PKIPath: viper.GetStringSlice("vault-pki-paths")[0],
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
				PKIPath:             viper.GetStringSlice("vault-pki-paths")[0],
				ClientVPNEndpointID: viper.GetString("client-vpn-endpoint-id"),
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
				PKIPath: viper.GetStringSlice("vault-pki-paths")[0],
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
