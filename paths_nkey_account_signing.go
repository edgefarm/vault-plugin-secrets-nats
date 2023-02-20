package natsbackend

import (
	"context"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
)

func pathAccountSigningNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/signing/" + framework.GenericNameRegex("signing") + "$",
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
				"signing": {
					Type:        framework.TypeString,
					Description: "signing identifier",
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
					Callback: b.pathAddAccountSigningNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountSigningNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountSigningNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountSigningNkey,
				},
			},
			HelpSynopsis:    `Manages account signing Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no account signing Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/signing/?$",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountSigningNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingNkeyFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	nkey, err := readAccountSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingNkeyFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(NkeyNotFoundError), nil
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathListAccountSigningNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listAccountSigningNkeys(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListNkeysFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteAccountSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	return readNkey(ctx, storage, path)
}

func deleteAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	return deleteNkey(ctx, storage, path)
}

func addAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	return addNkey(ctx, storage, path, nkeys.PrefixByteAccount, params, "account")
}

func listAccountSigningNkeys(ctx context.Context, storage logical.Storage, params NkeyParameters) ([]string, error) {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, "")
	return listNkeys(ctx, storage, path)
}

func getAccountSigningNkeyPath(operator string, account string, signing string) string {
	return "nkey/operator/" + operator + "/account/" + account + "/signing/" + signing
}
