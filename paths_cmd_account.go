package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

func pathCmdAccount(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator/account/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Account Name.",
				Required:    false,
			},
			"nkey_id": {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id.",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddAccountCmd,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddAccountCmd,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadAccountCmd,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteAccountCmd,
			},
		},
		HelpSynopsis:    `Manages account Cmd's.`,
		HelpDescription: ``,
	}
}

func (b *NatsBackend) pathAddAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get account storage
	account, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(data.Get("name").(string)))
	if err != nil {
		return logical.ErrorResponse("missing account"), err
	}

	// no storage exists, create new
	if account == nil {
		account = &Parameters[jwt.AccountClaims]{}
	}

	// set the values
	account.NKeyID = data.Get("nkey_id").(string)
	//account.TokenClaims.SigningKeys = data.Get("SigningKeys").([]string)

	return nil, nil
}

func (b *NatsBackend) pathReadAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(data.Get("name").(string)))
}

func (b *NatsBackend) pathDeleteAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, accountCmdPath(data.Get("name").(string)))
	if err != nil {
		return nil, fmt.Errorf("error deleting account: %w", err)
	}
	return nil, nil
}
