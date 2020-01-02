package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/gorilla/mux"
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

	// Use gorilla/mux as http router
	mux := mux.NewRouter()
	mux.HandleFunc("/crl", httpGetCRL).Methods("GET")
	mux.HandleFunc("/crl", httpUpdateCRL).Methods("POST")
	mux.HandleFunc("/revoke/{user}", httpRevokeUser).Methods("POST")
	mux.HandleFunc("/users", httpListUsers).Methods("GET")

	// Serve everything with our mux
	http.Handle("/", mux)

	log.Print("Started server")
	log.Printf("Listening on port :%v", serverOpts.port)

	// Start the server
	log.Fatal(http.ListenAndServe(":"+serverOpts.port, mux))
}

func httpRevokeUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	err := operations.RevokeUser(vaultAddr, vaultToken, "cvpn-pki", vars["user"])
	if err != nil {
		http.Error(w, "Couldn't revoke user "+vars["user"]+":\n"+err.Error(), http.StatusInternalServerError)
	}
	fmt.Fprintln(w, "Done")
}

func httpGetCRL(w http.ResponseWriter, r *http.Request) {
	crl, err := operations.GetCRL(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	fmt.Fprintln(w, string(crl))
}

func httpUpdateCRL(w http.ResponseWriter, r *http.Request) {
	// Update the crl
	err := operations.UpdateCRL(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// return the updated crl
	crl, err := operations.GetCRL(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	fmt.Fprintln(w, string(crl))
}

func httpListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := operations.ListUsers(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	b, err := json.MarshalIndent(users, "", "  ")
	fmt.Fprintln(w, string(b))
}
