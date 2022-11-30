package natsbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/validate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/exp/slices"
)

type AccountCmdConfig struct {
	Name        string
	NKeyID      string
	AccountPath string
	SigningKeys string
	jwt.OperatorLimits
}

const (
	AccountName validate.Key = iota
	AccountNKeyID
	AccountOperatorSigningKey
	AccountSigningKeys
	AccountLimitsNatsSubs
	AccountLimitsAccountConn
	AccountLimitsAccountLeafNodeConn
	AccountLimitsAccountImports
	AccountLimitsAccountExports
	AccountLimitsNatsData
	AccountLimitsNatsPayload
	AccountLimitsAccountWildcardExports
	AccountLimitsJetstreamMemStorage
	AccountLimitsJetstreamDiskStorage
	AccountLimitsJetstreamStreams
	AccountLimitsJetstreamConsumer
	AccountLimitsJetstreamMaxAckPending
	AccountLimitsJetstreamMemoryMaxStreamBytes
	AccountLimitsJetstreamDiskMaxStreamBytes
	AccountLimitsJetstreamMaxBytesRequired
)

var (
	cmdAccountFieldParams = map[validate.Key]string{
		AccountName:                                "name",
		AccountNKeyID:                              "nkey_id",
		AccountOperatorSigningKey:                  "operator_signing_key",
		AccountSigningKeys:                         "account_signing_keys",
		AccountLimitsNatsSubs:                      "limits_nats_subs",
		AccountLimitsNatsData:                      "limits_nats_data",
		AccountLimitsNatsPayload:                   "limits_nats_payload",
		AccountLimitsAccountImports:                "limits_account_imports",
		AccountLimitsAccountExports:                "limits_account_exports",
		AccountLimitsAccountWildcardExports:        "limits_account_wildcards",
		AccountLimitsAccountConn:                   "limits_account_conn",
		AccountLimitsAccountLeafNodeConn:           "limits_account_leaf",
		AccountLimitsJetstreamMemStorage:           "limits_jetstream_mem_storage",
		AccountLimitsJetstreamDiskStorage:          "limits_jetstream_disk_storage",
		AccountLimitsJetstreamStreams:              "limits_jetstream_streams",
		AccountLimitsJetstreamConsumer:             "limits_jetstream_consumer",
		AccountLimitsJetstreamMaxAckPending:        "limits_jetstream_max_ack_pending",
		AccountLimitsJetstreamMemoryMaxStreamBytes: "limits_jetstream_memory_max_stream_bytes",
		AccountLimitsJetstreamDiskMaxStreamBytes:   "limits_jetstream_disk_max_stream_bytes",
		AccountLimitsJetstreamMaxBytesRequired:     "limits_jetstream_max_bytes_required",
	}

	validPathCmdAccountFields []string = []string{
		cmdAccountFieldParams[AccountName],
		cmdAccountFieldParams[AccountNKeyID],
		cmdAccountFieldParams[AccountOperatorSigningKey],
		cmdAccountFieldParams[AccountSigningKeys],
		cmdAccountFieldParams[AccountLimitsNatsSubs],
		cmdAccountFieldParams[AccountLimitsAccountConn],
		cmdAccountFieldParams[AccountLimitsAccountLeafNodeConn],
		cmdAccountFieldParams[AccountLimitsAccountImports],
		cmdAccountFieldParams[AccountLimitsAccountExports],
		cmdAccountFieldParams[AccountLimitsNatsData],
		cmdAccountFieldParams[AccountLimitsNatsPayload],
		cmdAccountFieldParams[AccountLimitsAccountWildcardExports],
		cmdAccountFieldParams[AccountLimitsJetstreamMemStorage],
		cmdAccountFieldParams[AccountLimitsJetstreamDiskStorage],
		cmdAccountFieldParams[AccountLimitsJetstreamStreams],
		cmdAccountFieldParams[AccountLimitsJetstreamConsumer],
		cmdAccountFieldParams[AccountLimitsJetstreamMaxAckPending],
		cmdAccountFieldParams[AccountLimitsJetstreamMemoryMaxStreamBytes],
		cmdAccountFieldParams[AccountLimitsJetstreamDiskMaxStreamBytes],
		cmdAccountFieldParams[AccountLimitsJetstreamMaxBytesRequired],
	}
)

func pathCmdAccount(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator/account/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			cmdAccountFieldParams[AccountName]: {
				Type:        framework.TypeString,
				Description: "Account Name.",
				Required:    false,
			},
			cmdAccountFieldParams[AccountNKeyID]: {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id.",
				Required:    false,
			},
			cmdAccountFieldParams[AccountOperatorSigningKey]: {
				Type:        framework.TypeString,
				Description: "Explicitly specified operator signing key to sign the account.",
				Required:    false,
			},
			cmdAccountFieldParams[AccountSigningKeys]: {
				Type:        framework.TypeString,
				Description: "Comma seperated list of other account NKeys IDs that can be used to sign on behalf of the accounts NKey.",
				Required:    false,
				Default:     "",
			},
			cmdAccountFieldParams[AccountLimitsNatsSubs]: {
				Type:        framework.TypeInt,
				Description: "Max number of subscriptions (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsAccountConn]: {
				Type:        framework.TypeInt,
				Description: "Max number of active connections (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsAccountLeafNodeConn]: {
				Type:        framework.TypeInt,
				Description: "Max number of active leaf node connections (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsAccountImports]: {
				Type:        framework.TypeInt,
				Description: "Max number of imports (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsAccountExports]: {
				Type:        framework.TypeInt,
				Description: "Max number of exports (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsNatsData]: {
				Type:        framework.TypeInt,
				Description: "Max number of bytes (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsNatsPayload]: {
				Type:        framework.TypeInt,
				Description: "Max message payload (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsAccountWildcardExports]: {
				Type:        framework.TypeBool,
				Description: "Wildcards allowed in exports.",
				Default:     true,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamMemStorage]: {
				Type:        framework.TypeInt,
				Description: "Max number of bytes for memory storage  (-1 is unlimited / 0 disabled).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamDiskStorage]: {
				Type:        framework.TypeInt,
				Description: "Max number of bytes for disk storage (-1 is unlimited / 0 disabled).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamStreams]: {
				Type:        framework.TypeInt,
				Description: "Max number of streams (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamConsumer]: {
				Type:        framework.TypeInt,
				Description: "Max number of consumers (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamMaxAckPending]: {
				Type:        framework.TypeInt,
				Description: "Max ack pending of a Stream (-1 is unlimited).",
				Default:     -1,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamMemoryMaxStreamBytes]: {
				Type:        framework.TypeInt,
				Description: "Max bytes a memory backed stream can have. (0 means disabled/unlimited)",
				Default:     0,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamDiskMaxStreamBytes]: {
				Type:        framework.TypeInt,
				Description: "Max bytes a disk backed stream can have. (0 means disabled/unlimited)",
				Default:     0,
				Required:    false,
			},
			cmdAccountFieldParams[AccountLimitsJetstreamMaxBytesRequired]: {
				Type:        framework.TypeBool,
				Description: "Max bytes required by all Streams.",
				Default:     false,
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddAccountCmd,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddAccountCmd,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadAccountCmd,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteAccountCmd,
			},
		},
		HelpSynopsis:    `Manages account Cmd's.`,
		HelpDescription: ``,
	}
}

func (b *NatsBackend) pathAddAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := validate.ValidateFields(data.Raw, validPathCmdAccountFields)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	name := data.Get(cmdAccountFieldParams[AccountName]).(string)
	accountNKeyID := data.Get(cmdAccountFieldParams[AccountNKeyID]).(string)
	if accountNKeyID == "" {
		accountNKeyID = name
	}
	c := &AccountCmdConfig{
		Name:        name,
		NKeyID:      accountNKeyID,
		AccountPath: accountCmdPath(name),
		SigningKeys: data.Get(cmdAccountFieldParams[AccountSigningKeys]).(string),
		OperatorLimits: jwt.OperatorLimits{
			NatsLimits: jwt.NatsLimits{
				Subs:    int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsSubs]).(int)),
				Data:    int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsData]).(int)),
				Payload: int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsPayload]).(int)),
			},
			AccountLimits: jwt.AccountLimits{
				Conn:            int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountConn]).(int)),
				LeafNodeConn:    int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountLeafNodeConn]).(int)),
				Imports:         int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountImports]).(int)),
				Exports:         int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountExports]).(int)),
				WildcardExports: data.Get(cmdAccountFieldParams[AccountLimitsAccountWildcardExports]).(bool),
				DisallowBearer:  false,
			},
			JetStreamLimits: jwt.JetStreamLimits{
				MemoryStorage:        int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMemStorage]).(int)),
				DiskStorage:          int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamDiskStorage]).(int)),
				Streams:              int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamStreams]).(int)),
				Consumer:             int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamConsumer]).(int)),
				MaxAckPending:        int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMaxAckPending]).(int)),
				MemoryMaxStreamBytes: int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMemoryMaxStreamBytes]).(int)),
				DiskMaxStreamBytes:   int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamDiskMaxStreamBytes]).(int)),
				MaxBytesRequired:     data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMaxBytesRequired]).(bool),
			},
		},
	}

	// The following block handles the following cases:
	// 1. check if the signing key is provided as a parameter
	// 1.1 lookup the signing key in the storage and check if it is within the signing keys of the operator
	// 1.2 bail out with the corresponding error if anything fails
	// 2.
	var signingKeyId string
	paramSigningKey := data.Get(cmdAccountFieldParams[AccountOperatorSigningKey]).(string)
	operatorParams, err := b.getOperatorParams(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if operatorParams == nil {
		return logical.ErrorResponse(OperatorNotConfiguredError), nil
	}

	if paramSigningKey != "" {
		nkeyForParamSigningKey, err := getNkey(ctx, req.Storage, Operator, paramSigningKey)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		if nkeyForParamSigningKey == nil {
			return logical.ErrorResponse("signing key %q not found", paramSigningKey), nil
		}
		nkeyForParamSigningKeyInfo, err := convertSeed(nkeyForParamSigningKey.Seed)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		operatorSigningKeys := operatorParams.TokenClaims.SigningKeys
		if len(operatorSigningKeys) <= 0 {
			return nil, fmt.Errorf(NoAdditionalSigningKeysError)
		}
		if slices.Contains(operatorSigningKeys, nkeyForParamSigningKeyInfo.PublicKey) {
			signingKeyId = paramSigningKey
		} else {
			return nil, fmt.Errorf(NotInOperatorSigningKeysError)
		}
	} else {
		signingKeyId = operatorParams.NKeyID
	}

	// If StrictSigningKeyVerification is set to true, it must be checked if there are any
	// signing keys configured for the account to be able to sign users.
	if operatorParams.TokenClaims.StrictSigningKeyUsage {
		if len(data.Get(cmdAccountFieldParams[AccountSigningKeys]).(string)) <= 0 {
			return nil, fmt.Errorf(StrictSigningKeyUsageButNoKeyDefinedError)
		}
	}

	signingKey, err := getNkey(ctx, req.Storage, Operator, signingKeyId)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	err = b.AddAccountCmd(ctx, req.Storage, c, signingKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

func (b *NatsBackend) AddAccountCmd(ctx context.Context, s logical.Storage, c *AccountCmdConfig, signingKey *Nkey) error {

	// Lookup account signing keys
	accountSigningKeys := jwt.SigningKeys{}
	accountSigningKeysList := c.SigningKeys
	missingKeys := []string{}
	if len(accountSigningKeysList) > 0 {
		for _, rawKeyId := range strings.Split(accountSigningKeysList, ",") {
			sigingKeyId := strings.TrimSpace(rawKeyId)
			key, err := getNkey(ctx, s, Account, sigingKeyId)
			if err != nil {
				return err
			}
			if key == nil {
				missingKeys = append(missingKeys, sigingKeyId)
				continue
			}
			// convert operator key
			converted, err := convertSeed(key.Seed)
			if err != nil {
				return err
			}
			accountSigningKeys.Add(converted.PublicKey)
		}
		if len(missingKeys) > 0 {
			return errors.New(MissingAccountSigningKeysError + ": " + strings.Join(missingKeys, ","))
		}
	}

	// get account storage
	params, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, s, c.AccountPath)
	if err != nil {
		return fmt.Errorf(AccountMissingError)
	}
	// no storage exists, create new
	if params == nil {
		params = &Parameters[jwt.AccountClaims]{}
	}

	// if new nkey, delete old
	if params.NKeyID != "" && params.NKeyID != c.NKeyID {
		err = deleteNKey(ctx, s, Account, params.NKeyID)
		if err != nil {
			return err
		}
	}

	// create account nkey
	key, err := getNkey(ctx, s, Account, c.NKeyID)
	if err != nil {
		return fmt.Errorf(NKeyStorageAccessError)
	}
	if key == nil {
		key, err = createNkey(ctx, s, Account, c.NKeyID)
		if err != nil {
			return err
		}
	}

	// convert operator key
	convertedSigningKey, err := convertSeed(signingKey.Seed)
	if err != nil {
		return err
	}

	// convert account key
	converted, err := convertSeed(key.Seed)
	if err != nil {
		return err
	}

	// update params
	params.Name = c.Name
	params.NKeyID = c.NKeyID
	params.TokenID = c.NKeyID
	params.TokenClaims.SigningKeys = accountSigningKeys
	params.TokenClaims.Limits = c.OperatorLimits
	params.TokenClaims.Subject = converted.PublicKey
	params.TokenClaims.Name = c.Name

	err = updateAccountJwt(ctx, s, params, convertedSigningKey.KeyPair, c.Name)
	if err != nil {
		return err
	}

	// store operator parameters
	_, err = storeInStorage(ctx, s, c.AccountPath, params)
	if err != nil {
		return err
	}

	return nil
}

func (b *NatsBackend) pathReadAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(data.Get("name").(string)))
}

func (b *NatsBackend) pathDeleteAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, accountCmdPath(data.Get("name").(string)))
	if err != nil {
		return logical.ErrorResponse(AccountDeleteError+": %w", err), nil
	}
	return nil, nil
}

func updateAccountJwt(ctx context.Context, s logical.Storage, p *Parameters[jwt.AccountClaims], nkey nkeys.KeyPair, account string) error {
	token, err := getFromStorage[JwtToken](ctx, s, accountJwtPath(account))
	if err != nil {
		return err
	}
	if token == nil {
		token = &JwtToken{}
	}

	// create account jwt
	token.Jwt, err = p.TokenClaims.Encode(nkey)
	if err != nil {
		return err
	}

	err = addAccountJWT(ctx, s, token.Jwt, account)
	if err != nil {
		return err
	}

	return nil
}

func (b *NatsBackend) getAccountParams(ctx context.Context, req *logical.Request) (*Parameters[jwt.AccountClaims], error) {
	params, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, req.Storage, operatorCmdPath())
	if err != nil {
		return nil, fmt.Errorf(AccountMissingError)
	}
	return params, nil
}

func (b *NatsBackend) pathCmdAccountList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(entries), nil
}
