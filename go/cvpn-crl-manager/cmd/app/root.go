package app

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "cvpn-crl-manager",
		Short: "Client VPN Client Revocation List (CRL) management",
	}
	vaultAddr  string
	vaultToken string
)

// Execute runs the app
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", "", "Full URL of the vault server")
	rootCmd.MarkFlagRequired("vault-addr")
	rootCmd.PersistentFlags().StringVar(&vaultToken, "vault-token", "", "The token to authenticate to the vault server")
	// getCRLCmd.MarkFlagRequired("vault-token")

	viper.BindPFlag("vault-addr", rootCmd.PersistentFlags().Lookup("vault-addr"))
	viper.BindPFlag("vault-token", rootCmd.PersistentFlags().Lookup("vault-token"))
}

// initConfig reads ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}
