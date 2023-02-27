package natsbackend

import (
	"context"
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
)

func pathAccountNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed",
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
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountNkey,
				},
			},
			HelpSynopsis:    `Manages account Nkeys.`,
			HelpDescription: `On create/update: If no account Nkey seed is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	nkey, err := readAccountNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingNkeyFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(NkeyNotFoundError), nil
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathListAccountNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listAccountNkeys(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListNkeysFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteAccountNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getAccountNkeyPath(params.Operator, params.Account)
	return readNkey(ctx, storage, path)
}

func deleteAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountNkeyPath(params.Operator, params.Account)
	return deleteNkey(ctx, storage, path)
}

func addAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountNkeyPath(params.Operator, params.Account)
	return addNkey(ctx, storage, path, nkeys.PrefixByteAccount, params, "account")
}

func listAccountNkeys(ctx context.Context, storage logical.Storage, params NkeyParameters) ([]string, error) {
	path := getAccountNkeyPath(params.Operator, "")
	return listNkeys(ctx, storage, path)
}

func getAccountNkeyPath(operator string, account string) string {
	return "nkey/operator/" + operator + "/account/" + account
}
