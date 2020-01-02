package app

import (
	"encoding/json"
	"fmt"

	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/spf13/cobra"
)

// listUsersOptions is the options for the command
type listUsersOptions struct {
	user string
}

var listUsersOpts listUsersOptions

// listUsersCmd represents the revoke-user command
var listUsersCmd = &cobra.Command{
	Use:     "list-users",
	Short:   "Lists all the VPN users with their associated certificates",
	Long:    "",
	Example: "cvpn-crl-manager list-users --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX",
	Run:     runListUsers,
}

func init() {
	rootCmd.AddCommand(listUsersCmd)
}

func runListUsers(cmd *cobra.Command, args []string) {
	users, err := operations.ListUsers(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(users)
	fmt.Println(string(b))
}
