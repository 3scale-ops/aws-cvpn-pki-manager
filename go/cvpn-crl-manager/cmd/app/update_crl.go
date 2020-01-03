package app

import (
	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/vault"
	"github.com/spf13/cobra"
)

// updateCRLOptions is the options for the command
type updateCRLOptions struct {
	user string
}

var updateCRLOpts updateCRLOptions

// updateCRLCmd represents the revoke-user command
var updateCRLCmd = &cobra.Command{
	Use:     "update-crl",
	Short:   "Updates the Client Revokation List for the VPN",
	Long:    "",
	Example: "cvpn-crl-manager update-crl --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX",
	Run:     runUpdateCRL,
}

func init() {
	rootCmd.AddCommand(updateCRLCmd)
}

func runUpdateCRL(cmd *cobra.Command, args []string) {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		panic(err)
	}
	_, err = operations.UpdateCRL(client, "cvpn-pki")
	if err != nil {
		panic(err)
	}
}
