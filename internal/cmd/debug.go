package cmd

import (
	"fmt"

	"github.com/dotandev/hintents/internal/gasmodel"
	"github.com/dotandev/hintents/internal/logger"
	"github.com/dotandev/hintents/internal/rpc"
	"github.com/spf13/cobra"
)

var (
	networkFlag  string
	rpcURLFlag   string
	gasModelFlag string
)

var debugCmd = &cobra.Command{
	Use:   "debug <transaction-hash>",
	Short: "Debug a failed Soroban transaction",
	Long: `Fetch and prepare a transaction for simulation.

With optional custom gas model to match private network configurations.

Examples:
  erst debug <tx-hash>
  erst debug --network testnet <tx-hash>
  erst debug --gas-model ./custom-gas-model.json <tx-hash>`,
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		switch rpc.Network(networkFlag) {
		case rpc.Testnet, rpc.Mainnet, rpc.Futurenet:
		default:
			return fmt.Errorf("invalid network: %s", networkFlag)
		}

		if gasModelFlag != "" {
			model, err := gasmodel.ParseGasModel(gasModelFlag)
			if err != nil {
				return fmt.Errorf("failed to parse gas model: %w", err)
			}
			validation := model.ValidateStrict()
			if !validation.Valid {
				logger.Logger.Warn(validation.ErrorsAsString())
				return fmt.Errorf("gas model validation failed")
			}
			logger.Logger.Info("Gas model loaded", "network", model.NetworkID)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		txHash := args[0]
		var client *rpc.Client
		if rpcURLFlag != "" {
			client = rpc.NewClientWithURL(rpcURLFlag, rpc.Network(networkFlag))
		} else {
			client = rpc.NewClient(rpc.Network(networkFlag))
		}

		fmt.Printf("Debugging: %s\n", txHash)
		fmt.Printf("Network: %s\n", networkFlag)
		if rpcURLFlag != "" {
			fmt.Printf("RPC: %s\n", rpcURLFlag)
		}
		if gasModelFlag != "" {
			fmt.Printf("Gas Model: %s\n", gasModelFlag)
		}

		resp, err := client.GetTransaction(cmd.Context(), txHash)
		if err != nil {
			return fmt.Errorf("fetch failed: %w", err)
		}

		fmt.Printf("Transaction fetched. Envelope: %d bytes\n", len(resp.EnvelopeXdr))

		if gasModelFlag != "" {
			model, _ := gasmodel.ParseGasModel(gasModelFlag)
			fmt.Printf("\nCustom Gas Model:\n")
			fmt.Printf("  Network: %s\n", model.NetworkID)
			fmt.Printf("  Costs: %d (CPU: %d, Host: %d, Ledger: %d)\n",
				len(model.AllCosts()),
				len(model.CPUCosts),
				len(model.HostCosts),
				len(model.LedgerCosts),
			)
		}
		return nil
	},
}

func init() {
	debugCmd.Flags().StringVarP(&networkFlag, "network", "n", string(rpc.Mainnet), "Network (testnet, mainnet, futurenet)")
	debugCmd.Flags().StringVar(&rpcURLFlag, "rpc-url", "", "Custom RPC URL")
	debugCmd.Flags().StringVar(&gasModelFlag, "gas-model", "", "Custom gas model JSON file")
	rootCmd.AddCommand(debugCmd)
}
