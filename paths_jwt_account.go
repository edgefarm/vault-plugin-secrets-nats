package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
)

func pathAccountJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
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
				"jwt": {
					Type:        framework.TypeString,
					Description: "Account JWT to import.",
					Required:    false,
				},
				"use_nkey": {
					Type:        framework.TypeString,
					Description: "Use NKey to sign JWT.",
					Required:    false,
				},
				"signing_nkeys": {
					Type:        framework.TypeCommaStringSlice,
					Description: "NKeys to use to sign JWT.",
					Required:    false,
				},
				"account_claims_json": {
					Type:        framework.TypeString,
					Description: "Account Claims JSON to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountJWT,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountJWT,
				},
			},
			HelpSynopsis:    `Manages account JWT's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountJWT,
				},
			},
			HelpSynopsis:    `List account JWT's.`,
			HelpDescription: ``,
		},
	}
}

func (b *NatsBackend) pathAddAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	create := false
	if req.Operation == logical.CreateOperation {
		create = true
	}

	err = addAccountJWT(ctx, create, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingJWTFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	jwt, err := readAccountJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingJWTFailedError), nil
	}

	if jwt == nil {
		return logical.ErrorResponse(JwtNotFoundError), nil
	}

	return createResponseJWTData(jwt)
}

func (b *NatsBackend) pathListAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listAccountJWTs(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListJWTsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteAccountJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteJWTFailedError), nil
	}
	return nil, nil
}

func readAccountJWT(ctx context.Context, storage logical.Storage, params JWTParameters) (*JWTStorage, error) {
	path := getAccountJWTPath(params.Operator, params.Account)
	return readJWT(ctx, storage, path)
}

func deleteAccountJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	path := getAccountJWTPath(params.Operator, params.Account)
	return deleteJWT(ctx, storage, path)
}

func addAccountJWT(ctx context.Context, create bool, storage logical.Storage, params JWTParameters) error {
	if params.JWT == "" {
		return fmt.Errorf("account JWT is required")
	} else {
		err := validateJWT[jwt.AccountClaims](params.JWT)
		if err != nil {
			return err
		}
	}

	path := getAccountJWTPath(params.Operator, params.Account)
	return addJWT(ctx, create, storage, path, params)
}

func listAccountJWTs(ctx context.Context, storage logical.Storage, params JWTParameters) ([]string, error) {
	path := getAccountJWTPath(params.Operator, "")
	return listJWTs(ctx, storage, path)
}

func getAccountJWTPath(operator string, account string) string {
	return "jwt/operator/" + operator + "/account/" + account
}
