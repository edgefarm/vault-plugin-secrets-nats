package natsbackend

import (
	"context"
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/validate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	OperatorNKeyID validate.Key = iota
	OperatorSigningKeys
	OperatorStrictSigningKeyUsage
	OperatorAccountServerUrl
	OperatorSystemAccount
)

var (
	cmdOperatorFieldParams = map[validate.Key]string{
		OperatorNKeyID:                "nkey_id",
		OperatorSigningKeys:           "signing_keys",
		OperatorStrictSigningKeyUsage: "strict_signing_key_usage",
		OperatorAccountServerUrl:      "account_server_url",
		OperatorSystemAccount:         "system_account",
	}

	validPathCmdOperatorFields []string = []string{
		cmdOperatorFieldParams[OperatorNKeyID],
		cmdOperatorFieldParams[OperatorSigningKeys],
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
			cmdOperatorFieldParams[OperatorSigningKeys]: {
				Type:        framework.TypeStringSlice,
				Description: "Slice of other operator NKeys IDs that can be used to sign on behalf of the main operator identity.",
				Required:    false,
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
	err := validate.ValidateFields(data, validPathCmdOperatorFields)
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
	if params.NKeyID != "" && params.NKeyID != data.Get("nkey_id").(string) {
		err = deleteNKey(ctx, req.Storage, Operator, params.NKeyID)
		if err != nil {
			return nil, err
		}
	}

	//
	// if sys account nkey exists?
	// Y: -> get nkey
	// N: -> create nkey
	// if

	//

	// create operator nkey
	key, err := getNkey(ctx, req.Storage, Operator, data.Get("nkey_id").(string))
	if err != nil {
		return logical.ErrorResponse("error while accessing nkey storage"), err
	}
	if key == nil {
		key, err = createNkey(ctx, req.Storage, Operator, data.Get("nkey_id").(string))
		if err != nil {
			return nil, err
		}
	}
	// TODO add jwt for sys account

	// convert operator key
	converted, err := convertSeed(key.Seed)
	if err != nil {
		return nil, err
	}

	systemAccountNKeyID := data.Get(cmdOperatorFieldParams[OperatorSystemAccount]).(string)

	// check system account
	sa, err := getNkey(ctx, req.Storage, Account, systemAccountNKeyID)
	if err != nil {
		return logical.ErrorResponse("error while accessing nkey storage"), err
	}

	// create system account
	if sa == nil {
		sa, err = createNkey(ctx, req.Storage, Account, systemAccountNKeyID)
		if err != nil {
			return nil, err
		}
	}
	// convert operator key
	convertedSysAccountKey, err := convertSeed(sa.Seed)
	if err != nil {
		return nil, err
	}

	// update params
	params.Name = "operator"
	params.NKeyID = data.Get(cmdOperatorFieldParams[OperatorNKeyID]).(string)
	params.TokenClaims.SigningKeys = data.Get(cmdOperatorFieldParams[OperatorSigningKeys]).([]string)
	params.TokenClaims.StrictSigningKeyUsage = data.Get(cmdOperatorFieldParams[OperatorStrictSigningKeyUsage]).(bool)
	params.TokenClaims.AccountServerURL = data.Get(cmdOperatorFieldParams[OperatorAccountServerUrl]).(string)
	params.TokenClaims.SystemAccount = convertedSysAccountKey.PublicKey
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

func (b *NatsBackend) getOperatorParams(ctx context.Context, req *logical.Request) (*Parameters[jwt.OperatorClaims], error) {
	params, err := getFromStorage[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
	if err != nil {
		return nil, fmt.Errorf("missing operator")
	}
	return params, nil
}
