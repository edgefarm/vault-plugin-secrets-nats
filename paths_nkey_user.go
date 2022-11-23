package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUserNkey(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "nkey/user/" + framework.GenericNameRegex("name") + "$",
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
				Callback: b.pathAddUserNkey,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddUserNkey,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadUserNkey,
			},
		},
		HelpSynopsis:    `Manages user Nkey keypairs.`,
		HelpDescription: `On Create or Update: If no user Nkey keypair is passed, a corresponding Nkey is generated.`,
	}
}

func (b *NatsBackend) pathAddUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "user")
}

func (b *NatsBackend) pathReadUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, "user")
}

func (b *NatsBackend) pathUserNkeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "nkey/user/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
