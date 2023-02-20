package natsbackend

import (
	"context"
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

func pathOperatorJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"jwt": {
					Type:        framework.TypeString,
					Description: "Operator JWT to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorJWT,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorJWT,
				},
			},
			HelpSynopsis:    `Manages operator JWT.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListOperatorJWTs,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingJWTFailedError), nil
	}
	return nil, nil

}

func (b *NatsBackend) pathReadOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	jwt, err := readOperatorJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingJWTFailedError), nil
	}

	if jwt == nil {
		return logical.ErrorResponse(JwtNotFoundError), nil
	}

	return createResponseJWTData(jwt)
}

func (b *NatsBackend) pathListOperatorJWTs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	entries, err := listOperatorJWTs(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(ListJWTsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteOperatorJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteJWTFailedError), nil
	}
	return nil, nil
}

func readOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) (*JWTStorage, error) {
	path := getOperatorJWTPath(params.Operator)
	return readJWT(ctx, storage, path)
}

func deleteOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	path := getOperatorJWTPath(params.Operator)
	return deleteJWT(ctx, storage, path)
}

func addOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	if params.JWT == "" {
		return fmt.Errorf("operator JWT is required")
	} else {
		err := validateJWT[jwt.OperatorClaims](params.JWT)
		if err != nil {
			return err
		}
	}

	path := getOperatorJWTPath(params.Operator)
	return addJWT(ctx, storage, path, params)
}

func listOperatorJWTs(ctx context.Context, storage logical.Storage) ([]string, error) {
	path := getOperatorJWTPath("")
	return listJWTs(ctx, storage, path)
}

func getOperatorJWTPath(operator string) string {
	return "jwt/operator/" + operator
}
