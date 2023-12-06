package natsbackend

import (
	"context"
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/rs/zerolog/log"
)

func pathUserJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"jwt": {
					Type:        framework.TypeString,
					Description: "User JWT to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserJWT,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserJWT,
				},
			},
			HelpSynopsis:    `Manages user JWT's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
					Callback: b.pathListUserJWTs,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addUserJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingJWTFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	jwt, err := readUserJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingJWTFailedError), nil
	}

	if jwt == nil {
		return logical.ErrorResponse(JwtNotFoundError), nil
	}

	return createResponseJWTData(jwt)
}

func (b *NatsBackend) pathListUserJWTs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserJWTs(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListJWTsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteUserJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteJWTFailedError), nil
	}
	return nil, nil
}

func readUserJWT(ctx context.Context, storage logical.Storage, params JWTParameters) (*JWTStorage, error) {
	path := getUserJWTPath(params.Operator, params.Account, params.User)
	return readJWT(ctx, storage, path)
}

func deleteUserJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	path := getUserJWTPath(params.Operator, params.Account, params.User)
	return deleteJWT(ctx, storage, path)
}

func addUserJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("user", params.User).
		Msg("create/update user jwt")

	if params.JWT == "" {
		return fmt.Errorf("user JWT is required")
	} else {
		err := validateJWT[jwt.UserClaims](params.JWT)
		if err != nil {
			return err
		}
	}

	path := getUserJWTPath(params.Operator, params.Account, params.User)
	err := addJWT(ctx, storage, path, params)
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

func listUserJWTs(ctx context.Context, storage logical.Storage, params JWTParameters) ([]string, error) {
	path := getUserJWTPath(params.Operator, params.Account, "")
	return listJWTs(ctx, storage, path)
}

func getUserJWTPath(operator string, account string, user string) string {
	return "jwt/operator/" + operator + "/account/" + account + "/user/" + user
}
