package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathOperatorNkey(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "nkey/operator/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Nkey.",
				Required:    false,
			},
			"seed": {
				Type:        framework.TypeString,
				Description: "Nkey seed - Base64 Encoded.",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddOperatorNkey,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddOperatorNkey,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadOperatorNkey,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathOperatorNkeysDelete,
			},
		},
		HelpSynopsis:    `Manages operator Nkey keypairs.`,
		HelpDescription: `On Create or Update: If no operator Nkey keypair is passed, a corresponding Nkey is generated.`,
	}
}

func (b *NatsBackend) pathAddOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, Operator)
}

func (b *NatsBackend) pathReadOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, Operator)
}

func (b *NatsBackend) pathOperatorNkeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "nkey/operator/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathOperatorNkeysDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathDeleteNkey(ctx, req, data, Operator)
}
