package natsbackend

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/validate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	OperatorNKeyID validate.Key = iota
	OperatorSigningKeysIds
	OperatorStrictSigningKeyUsage
	OperatorAccountServerUrl
	OperatorSystemAccount
)

var (
	cmdOperatorFieldParams = map[validate.Key]string{
		OperatorNKeyID:                "nkey_id",
		OperatorSigningKeysIds:        "operator_signing_keys",
		OperatorStrictSigningKeyUsage: "strict_signing_key_usage",
		OperatorAccountServerUrl:      "account_server_url",
		OperatorSystemAccount:         "system_account",
	}

	validPathCmdOperatorFields []string = []string{
		cmdOperatorFieldParams[OperatorNKeyID],
		cmdOperatorFieldParams[OperatorSigningKeysIds],
		cmdOperatorFieldParams[OperatorStrictSigningKeyUsage],
		cmdOperatorFieldParams[OperatorAccountServerUrl],
		cmdOperatorFieldParams[OperatorSystemAccount],
	}
)

func pathCmdOperator(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator",
		Fields: map[string]*framework.FieldSchema{
			cmdOperatorFieldParams[OperatorNKeyID]: {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id.",
				Required:    false,
				Default:     "operator",
			},
			cmdOperatorFieldParams[OperatorSigningKeysIds]: {
				Type:        framework.TypeString,
				Description: "Comma seperated list of other operator NKeys IDs that can be used to sign on behalf of the main operator identity.",
				Required:    false,
				Default:     "",
			},
			cmdOperatorFieldParams[OperatorStrictSigningKeyUsage]: {
				Type:        framework.TypeBool,
				Description: "Signing of subordinate objects will require signing keys.",
				Required:    false,
				Default:     false,
			},
			cmdOperatorFieldParams[OperatorAccountServerUrl]: {
				Type:        framework.TypeString,
				Description: "Account Server URL for pushing jwt's.",
				Required:    false,
			},
			cmdOperatorFieldParams[OperatorSystemAccount]: {
				Type:        framework.TypeString,
				Description: "Create system account if not exists.",
				Required:    false,
				Default:     "SYS",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddOperatorCmd,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddOperatorCmd,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadOperatorCmd,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteOperatorCmd,
			},
		},
		HelpSynopsis:    `Manages operator Cmd.`,
		HelpDescription: ``,
	}
}

func (b *NatsBackend) pathAddOperatorCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := validate.ValidateFields(data.Raw, validPathCmdOperatorFields)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// get Operator storage
	params, err := getFromStorage[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
	if err != nil {
		return logical.ErrorResponse(OperatorMissingError), nil
	}
	// no storage exists, create new
	if params == nil {
		params = &Parameters[jwt.OperatorClaims]{}
	}

	// if new nkey, delete old
	if params.NKeyID != "" && params.NKeyID != data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string) {
		err = deleteNKey(ctx, req.Storage, Operator, params.NKeyID)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// create operator nkey
	key, err := getNkey(ctx, req.Storage, Operator, data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string))
	if err != nil {
		return logical.ErrorResponse(NKeyStorageAccessError), nil
	}
	if key == nil {
		key, err = createNkey(ctx, req.Storage, Operator, data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// convert operator key
	converted, err := convertSeed(key.Seed)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Lookup operator signing keys
	operatorSigningKeys := jwt.StringList{}
	operatorSigningKeysList := data.Get(cmdOperatorFieldParams[OperatorSigningKeysIds]).(string)
	missingKeys := []string{}
	if len(operatorSigningKeysList) > 0 {
		for _, rawKeyId := range strings.Split(operatorSigningKeysList, ",") {
			sigingKeyId := strings.TrimSpace(rawKeyId)
			key, err := getNkey(ctx, req.Storage, Operator, sigingKeyId)
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}
			if key == nil {
				missingKeys = append(missingKeys, sigingKeyId)
				continue
			}
			// convert operator key
			converted, err := convertSeed(key.Seed)
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}
			operatorSigningKeys = append(operatorSigningKeys, converted.PublicKey)
		}
		if len(missingKeys) > 0 {
			return logical.ErrorResponse(MissingOperatorSigningKeysError + ": " + strings.Join(missingKeys, ",")), nil
		}
	}
	// update params
	nkeyID := data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string)
	params.Name = "operator"
	params.NKeyID = nkeyID
	params.TokenID = nkeyID
	params.TokenClaims.SigningKeys = operatorSigningKeys
	params.TokenClaims.StrictSigningKeyUsage = data.Get(cmdOperatorFieldParams[OperatorStrictSigningKeyUsage]).(bool)
	params.TokenClaims.AccountServerURL = data.Get(cmdOperatorFieldParams[OperatorAccountServerUrl]).(string)
	params.TokenClaims.SystemAccount = data.Get(cmdOperatorFieldParams[OperatorSystemAccount]).(string)
	params.TokenClaims.Subject = converted.PublicKey
	err = updateOperatorJwt(ctx, req.Storage, params, converted.KeyPair)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	systemAccountName := data.Get(cmdOperatorFieldParams[OperatorSystemAccount]).(string)
	err = b.AddAccountCmd(ctx, req.Storage, &AccountCmdConfig{
		Name:        systemAccountName,
		NKeyID:      systemAccountName,
		AccountPath: accountCmdPath(systemAccountName),
		OperatorLimits: jwt.OperatorLimits{
			NatsLimits: jwt.NatsLimits{
				Subs:    -1,
				Data:    -1,
				Payload: -1,
			},
			AccountLimits: jwt.AccountLimits{
				Imports:         -1,
				Exports:         -1,
				WildcardExports: true,
				DisallowBearer:  false,
				Conn:            -1,
				LeafNodeConn:    -1,
			},
			JetStreamLimits: jwt.JetStreamLimits{
				MemoryStorage:        -1,
				DiskStorage:          -1,
				Streams:              -1,
				Consumer:             -1,
				MaxAckPending:        -1,
				MemoryMaxStreamBytes: 0,
				DiskMaxStreamBytes:   0,
				MaxBytesRequired:     false,
			},
		},
	}, key)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// store operator parameters
	_, err = storeInStorage(ctx, req.Storage, operatorCmdPath(), params)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return nil, nil
}

func (b *NatsBackend) pathReadOperatorCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
}

func (b *NatsBackend) pathDeleteOperatorCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get Operator storage
	params, err := getFromStorage[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
	if err != nil {
		return logical.ErrorResponse(OperatorMissingError), err
	}

	// delete referenced nkey
	if params != nil {
		err = deleteNKey(ctx, req.Storage, Operator, params.NKeyID)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// delete operator storage
	err = req.Storage.Delete(ctx, operatorCmdPath())
	if err != nil {
		return nil, fmt.Errorf(DeletingOperatorError+": %w", err)
	}
	return nil, nil
}

func updateOperatorJwt(ctx context.Context, s logical.Storage, p *Parameters[jwt.OperatorClaims], nkey nkeys.KeyPair) error {
	token, err := getFromStorage[JwtToken](ctx, s, operatorJwtPath())
	if err != nil {
		return err
	}
	if token == nil {
		token = &JwtToken{}
	}

	// create operator jwt
	token.Jwt, err = p.TokenClaims.Encode(nkey)
	if err != nil {
		return err
	}

	err = addOperatorJWT(ctx, s, token.Jwt)
	if err != nil {
		return err
	}

	return nil
}

func (b *NatsBackend) getOperatorParams(ctx context.Context, s logical.Storage) (*Parameters[jwt.OperatorClaims], error) {
	params, err := getFromStorage[Parameters[jwt.OperatorClaims]](ctx, s, operatorCmdPath())
	if err != nil {
		return nil, fmt.Errorf(OperatorMissingError)
	}
	return params, nil
}
