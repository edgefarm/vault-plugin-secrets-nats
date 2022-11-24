package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAccountNkey(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "nkey/account/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
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
				Callback: b.pathAddAccountNkey,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddAccountNkey,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadAccountNkey,
			},
		},
		HelpSynopsis:    `Manages account Nkey keypairs.`,
		HelpDescription: `On Create or Update: If no account Nkey keypair is passed, a corresponding Nkey is generated.`,
	}
}

func (b *NatsBackend) pathAddAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, Account)
}

func (b *NatsBackend) pathReadAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, Account)
}

func (b *NatsBackend) pathAccountNkeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "nkey/account/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
