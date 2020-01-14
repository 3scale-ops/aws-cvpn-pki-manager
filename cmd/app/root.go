package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "aws-cvpn-pki-manager",
		Short: "Client VPN Client Revocation List (CRL) management",
	}
	vaultAddr string
)

// Execute runs the app
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", "", "Full URL of the vault server")
	viper.BindPFlag("vault-addr", rootCmd.PersistentFlags().Lookup("vault-addr"))
	viper.SetDefault("vault-addr", "http://127.0.0.1:8200")

	viper.SetEnvPrefix("ACPM")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}
