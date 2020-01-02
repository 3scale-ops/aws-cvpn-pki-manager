package app

import (
	"fmt"

	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/spf13/cobra"
)

// getCRLOptions is the options for the command
type getCRLOptions struct {
	user string
}

var getCRLOpts getCRLOptions

// getCRLCmd represents the revoke-user command
var getCRLCmd = &cobra.Command{
	Use:     "get-crl",
	Short:   "Revokes all the certificates associated with a VPN user",
	Long:    "",
	Example: "cvpn-crl-manager get-crl --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX",
	Run:     runGetCRL,
}

func init() {
	rootCmd.AddCommand(getCRLCmd)
}

func runGetCRL(cmd *cobra.Command, args []string) {
	crl, err := operations.GetCRL(vaultAddr, vaultToken, "cvpn-pki")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(crl))
}
