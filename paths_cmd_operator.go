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
		OperatorSigningKeysIds:        "signing_keys",
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
		return logical.ErrorResponse("missing operator"), err
	}
	// no storage exists, create new
	if params == nil {
		params = &Parameters[jwt.OperatorClaims]{}
	}

	// if new nkey, delete old
	if params.NKeyID != "" && params.NKeyID != data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string) {
		err = deleteNKey(ctx, req.Storage, Operator, params.NKeyID)
		if err != nil {
			return nil, err
		}
	}

	// create operator nkey
	key, err := getNkey(ctx, req.Storage, Operator, data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string))
	if err != nil {
		return logical.ErrorResponse("error while accessing nkey storage"), err
	}
	if key == nil {
		key, err = createNkey(ctx, req.Storage, Operator, data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string))
		if err != nil {
			return nil, err
		}
	}

	// convert operator key
	converted, err := convertSeed(key.Seed)
	if err != nil {
		return nil, err
	}

	// Lookup operator signing keys
	operatorSigningKeys := jwt.StringList{}
	operatorSigningKeysList := data.Get(cmdOperatorFieldParams[OperatorSigningKeysIds]).(string)
	if len(operatorSigningKeysList) > 0 {
		for _, rawKeyId := range strings.Split(operatorSigningKeysList, ",") {
			sigingKeyId := strings.TrimSpace(rawKeyId)
			key, err := getNkey(ctx, req.Storage, Operator, sigingKeyId)
			if err != nil {
				return nil, err
			}
			if key == nil {
				return logical.ErrorResponse("signing key does not exist: %s", sigingKeyId), nil

			}
			// convert operator key
			converted, err := convertSeed(key.Seed)
			if err != nil {
				return nil, err
			}
			operatorSigningKeys = append(operatorSigningKeys, converted.PublicKey)
		}
	}
	// update params
	params.Name = "operator"
	params.NKeyID = data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string)
	params.TokenClaims.SigningKeys = operatorSigningKeys
	params.TokenClaims.StrictSigningKeyUsage = data.Get(cmdOperatorFieldParams[OperatorStrictSigningKeyUsage]).(bool)
	params.TokenClaims.AccountServerURL = data.Get(cmdOperatorFieldParams[OperatorAccountServerUrl]).(string)
	params.TokenClaims.SystemAccount = data.Get(cmdOperatorFieldParams[OperatorSystemAccount]).(string)
	params.TokenClaims.Subject = converted.PublicKey
	err = updateOperatorJwt(ctx, req.Storage, params, converted.KeyPair)
	if err != nil {
		return nil, err
	}

	// create siging keys
	seed, err := converted.KeyPair.Seed() //.StdEncoding.DecodeString(okey.Seed)
	if err != nil {
		return nil, err
	}
	_, err = nkeys.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	for _, key := range params.TokenClaims.SigningKeys {
		// get signing key
		skey, err := getNkey(ctx, req.Storage, Operator, key)
		if err != nil {
			return logical.ErrorResponse("error while accessing nkey storage"), err
		}
		// create signing key if it doesn't exist
		if skey == nil {
			_, err = createNkey(ctx, req.Storage, Operator, key)
			if err != nil {
				return nil, err
			}
		}
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
		return nil, err
	}

	// store operator parameters
	_, err = storeInStorage(ctx, req.Storage, operatorCmdPath(), params)
	if err != nil {
		return nil, err
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
		return logical.ErrorResponse("missing operator"), err
	}

	// delete referenced nkey
	if params != nil {
		err = deleteNKey(ctx, req.Storage, Operator, params.NKeyID)
		if err != nil {
			return nil, err
		}
	}

	// delete operator storage
	err = req.Storage.Delete(ctx, operatorCmdPath())
	if err != nil {
		return nil, fmt.Errorf("error deleting operator: %w", err)
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
		return nil, fmt.Errorf("missing operator")
	}
	return params, nil
}
