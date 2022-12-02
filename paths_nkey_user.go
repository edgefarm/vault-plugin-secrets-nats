package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUserNkey(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "nkey/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Nkey.",
				Required:    false,
			},
			"account_name": {
				Type:        framework.TypeString,
				Description: "Account Name",
				Required:    true,
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
	return b.pathAddNkey(ctx, req, data, User)
}

func (b *NatsBackend) pathReadUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, User)
}

func (b *NatsBackend) pathUserNkeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "nkey/user/")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(entries), nil
}
