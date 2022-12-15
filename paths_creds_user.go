package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func pathUserCreds(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"creds": {
					Type:        framework.TypeString,
					Description: "User Creds to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserCreds,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserCreds,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserCreds,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserCreds,
				},
			},
			HelpSynopsis:    `Manages user Creds's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
					Callback: b.pathListUserCreds,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params CredsParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	create := false
	if req.Operation == logical.CreateOperation {
		create = true
	}

	err = addUserCreds(ctx, create, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingCredsFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params CredsParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	creds, err := readUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingCredsFailedError), nil
	}

	if creds == nil {
		return logical.ErrorResponse(JwtNotFoundError), nil
	}

	return createResponseCredsData(creds)
}

func (b *NatsBackend) pathListUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params CredsParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListCredsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params CredsParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteCredsFailedError), nil
	}
	return nil, nil
}

func readUserCreds(ctx context.Context, storage logical.Storage, params CredsParameters) (*CredsStorage, error) {
	path := getUserCredsPath(params.Operator, params.Account, params.User)
	return readCreds(ctx, storage, path)
}

func deleteUserCreds(ctx context.Context, storage logical.Storage, params CredsParameters) error {
	path := getUserCredsPath(params.Operator, params.Account, params.User)
	return deleteCreds(ctx, storage, path)
}

func addUserCreds(ctx context.Context, create bool, storage logical.Storage, params CredsParameters) error {
	if params.Creds == "" {
		return fmt.Errorf("user Creds is required")
	}

	path := getUserCredsPath(params.Operator, params.Account, params.User)
	return addCreds(ctx, create, storage, path, params)
}

func listUserCreds(ctx context.Context, storage logical.Storage, params CredsParameters) ([]string, error) {
	path := getUserCredsPath(params.Operator, params.Account, "")
	return listCreds(ctx, storage, path)
}

func getUserCredsPath(operator string, account string, user string) string {
	return "creds/operator/" + operator + "/account/" + account + "/user/" + user
}
