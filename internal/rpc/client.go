package rpc

import (
	"context"
	"fmt"

	"github.com/stellar/go/clients/horizonclient"
)

// Client handles interactions with the Stellar Network
type Client struct {
	Horizon *horizonclient.Client
}

// NewClient creates a new RPC client (defaults to Public Network for now)
func NewClient() *Client {
	return &Client{
		Horizon: horizonclient.DefaultPublicNetClient,
	}
}

// TransactionResponse contains the raw XDR fields needed for simulation
type TransactionResponse struct {
	EnvelopeXdr   string
	ResultXdr     string
	ResultMetaXdr string
}

// GetTransaction fetches the transaction details and full XDR data
func (c *Client) GetTransaction(ctx context.Context, hash string) (*TransactionResponse, error) {
	tx, err := c.Horizon.TransactionDetail(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
	}

	return &TransactionResponse{
		EnvelopeXdr:   tx.EnvelopeXdr,
		ResultXdr:     tx.ResultXdr,
		ResultMetaXdr: tx.ResultMetaXdr,
	}, nil
}
