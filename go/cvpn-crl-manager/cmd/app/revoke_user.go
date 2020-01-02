package app

import (
	"github.com/3scale/platform/go/cvpn-ctl-manager/pkg/operations"
	"github.com/spf13/cobra"
)

// revokeUserOptions is the options for the command
type revokeUserOptions struct {
	user string
}

var revokeUserOpts revokeUserOptions

// revokeUserCmd represents the revoke-user command
var revokeUserCmd = &cobra.Command{
	Use:     "revoke-user",
	Short:   "Revokes all the certificates associated with a VPN user",
	Long:    "",
	Example: "cvpn-crl-manager revoke-user --user roivaz --vault-server http://localhost:8200 --vault-token s.XXXXXXXXX",
	Run:     runRevokeUser,
}

func init() {
	rootCmd.AddCommand(revokeUserCmd)
	revokeUserCmd.Flags().StringVar(&revokeUserOpts.user, "user", "", "The user to revoke")
	revokeUserCmd.MarkFlagRequired("user")
}

func runRevokeUser(cmd *cobra.Command, args []string) {
	err := operations.RevokeUser(vaultAddr, vaultToken, "cvpn-pki", revokeUserOpts.user)
	if err != nil {
		panic(err)
	}
}
