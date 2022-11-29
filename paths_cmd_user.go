package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

func pathCmdUser(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "User Name.",
				Required:    false,
			},
			"account_name": {
				Type:        framework.TypeString,
				Description: "Account Name.",
				Required:    false,
			},
			"NKeyID": {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id.",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddUserCmd,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddUserCmd,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadUserCmd,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteUserCmd,
			},
		},
		HelpSynopsis:    `Manages user Cmd's.`,
		HelpDescription: ``,
	}
}

func (b *NatsBackend) pathAddUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing account name"), nil
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing user name"), nil
	}

	// get Operator storage
	user, err := getFromStorage[Parameters[jwt.UserClaims]](ctx, req.Storage, userCmdPath(account, name))
	if err != nil {
		return logical.ErrorResponse("missing user"), err
	}

	// no storage exists, create new
	if user == nil {
		user = &Parameters[jwt.UserClaims]{}
	}

	// set the values
	user.NKeyID = data.Get("NKeyID").(string)

	return nil, nil
}

func (b *NatsBackend) pathReadUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing account name"), nil
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing user name"), nil
	}

	return readOperation[Parameters[jwt.UserClaims]](ctx, req.Storage, userJwtPath(account, name))
}

func (b *NatsBackend) pathDeleteUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, userCmdPath(data.Get("account").(string), data.Get("name").(string)))
	if err != nil {
		return logical.ErrorResponse("error deleting user: %w", err), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathCmdUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accountName := d.Get("account_name").(string)
	entries, err := req.Storage.List(ctx, "cmd/operator/account/"+accountName+"/user")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(entries), nil
}
