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

func pathOperatorNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
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
					Callback: b.pathAddOperatorNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorNkey,
				},
			},
			HelpSynopsis:    `Manages operator Nkeys.`,
			HelpDescription: `On create/update: If no operator Nkey seed is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListOperatorNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	nkey, err := readOperatorNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingNkeyFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(NkeyNotFoundError), nil
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathListOperatorNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	entries, err := listOperatorNkeys(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(ListNkeysFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteOperatorNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getOperatorNkeyPath(params.Operator)
	return readNkey(ctx, storage, path)
}

func deleteOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getOperatorNkeyPath(params.Operator)
	return deleteNkey(ctx, storage, path)
}

func addOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).
		Msg("create/update operator nkey")

	path := getOperatorNkeyPath(params.Operator)
	err := addNkey(ctx, storage, path, nkeys.PrefixByteOperator, params, "operator")
	if err != nil {
		return err
	}

	iParams := IssueOperatorParameters{
		Operator: params.Operator,
	}

	issue, err := readOperatorIssue(ctx, storage, iParams)
	if err != nil {
		return err
	}
	if issue == nil {
		//ignore error, try to create issue
		addOperatorIssue(ctx, storage, iParams)
	}
	return nil
}

func listOperatorNkeys(ctx context.Context, storage logical.Storage) ([]string, error) {
	path := getOperatorNkeyPath("")
	return listNkeys(ctx, storage, path)
}

func getOperatorNkeyPath(operator string) string {
	return "nkey/operator/" + operator
}
