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
	port string
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
}

func runServer(cmd *cobra.Command, args []string) {

	// Serve everything with our mux

	// Create a singe shared cient to talk to the
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
		err := operations.IssueClientCertificate(client, "cvpn-pki", vars["user"], "cvpn-client")
		if err != nil {
			http.Error(w, "Couldn't revoke user "+vars["user"]+":\n"+err.Error(), http.StatusInternalServerError)
		}
		fmt.Fprintln(w, "Done")
	}
}

func revokeUserHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		err := operations.RevokeUser(client, "cvpn-pki", vars["user"])
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Internal error, couldn't revoke user "+vars["user"]+":\n", http.StatusInternalServerError)
		}
		fmt.Fprintln(w, "Done")
	}
}

func getCRLHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		crl, err := operations.GetCRL(client, "cvpn-pki")
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Internal error, coult'n retrieve the CRL", http.StatusInternalServerError)
		}
		fmt.Fprintln(w, string(crl))
	}
}

func updateCRLHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Update the crl
		crl, err := operations.UpdateCRL(client, "cvpn-pki")
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Internal error, CRL could not be updated", http.StatusInternalServerError)
		}

		fmt.Fprintln(w, string(crl))
	}
}

func listUsersHandler(client *api.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := operations.ListUsers(client, "cvpn-pki")
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Internal error, could'n retrieve the user list", http.StatusInternalServerError)
		}
		b, err := json.MarshalIndent(users, "", "  ")
		fmt.Fprintln(w, string(b))
	}
}
