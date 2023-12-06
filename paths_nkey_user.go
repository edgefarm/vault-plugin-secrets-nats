package natsbackend

import (
	"context"
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

func pathUserNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"user": {
					Type:        framework.TypeString,
					Description: "user identifier",
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
					Callback: b.pathAddUserNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserNkey,
				},
			},
			HelpSynopsis:    `Manages user Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no user Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
					Callback: b.pathListUserNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addUserNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	nkey, err := readUserNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingNkeyFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(NkeyNotFoundError), nil
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathListUserNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserNkeys(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListNkeysFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteUserNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readUserNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getUserNkeyPath(params.Operator, params.Account, params.User)
	return readNkey(ctx, storage, path)
}

func deleteUserNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getUserNkeyPath(params.Operator, params.Account, params.User)
	return deleteNkey(ctx, storage, path)
}

func addUserNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("user", params.User).
		Msg("create/update user nkey")

	path := getUserNkeyPath(params.Operator, params.Account, params.User)
	err := addNkey(ctx, storage, path, nkeys.PrefixByteUser, params, "user")
	if err != nil {
		return err
	}

	iParams := IssueUserParameters{
		Operator: params.Operator,
		Account:  params.Account,
		User:     params.User,
	}

	issue, err := readUserIssue(ctx, storage, iParams)
	if err != nil {
		return err
	}
	if issue == nil {
		//ignore error, try to create issue
		addUserIssue(ctx, storage, iParams)
	}
	return nil
}

func listUserNkeys(ctx context.Context, storage logical.Storage, params NkeyParameters) ([]string, error) {
	path := getUserNkeyPath(params.Operator, params.Account, "")
	return listNkeys(ctx, storage, path)
}

func getUserNkeyPath(operator string, account string, user string) string {
	return "nkey/operator/" + operator + "/account/" + account + "/user/" + user
}
