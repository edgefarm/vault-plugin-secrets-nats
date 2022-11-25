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
	AccountName validate.Key = iota
	AccountNKeyID
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
	err := validate.ValidateFields(data, validPathCmdAccountFields)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	accountName := data.Get("name").(string)
	// get account storage
	params, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(accountName))
	if err != nil {
		return logical.ErrorResponse("missing account"), err
	}
	// no storage exists, create new
	if params == nil {
		params = &Parameters[jwt.AccountClaims]{}
	}

	// if new nkey, delete old
	if params.NKeyID != "" && params.NKeyID != data.Get("nkey_id").(string) {
		err = deleteNKey(ctx, req.Storage, Account, params.NKeyID)
		if err != nil {
			return nil, err
		}
	}

	// create account nkey
	key, err := getNkey(ctx, req.Storage, Account, data.Get("nkey_id").(string))
	if err != nil {
		return logical.ErrorResponse("error while accessing nkey storage"), err
	}
	if key == nil {
		key, err = createNkey(ctx, req.Storage, Account, data.Get("nkey_id").(string))
		if err != nil {
			return nil, err
		}
	}

	operatorParams, err := b.getOperatorParams(ctx, req)
	if err != nil {
		return nil, err
	}
	signingKey, err := getNkey(ctx, req.Storage, Operator, operatorParams.NKeyID)
	if err != nil {
		return nil, err
	}

	// convert operator key
	convertedSigningKey, err := convertSeed(signingKey.Seed)
	if err != nil {
		return nil, err
	}

	// convert account key
	converted, err := convertSeed(key.Seed)
	if err != nil {
		return nil, err
	}

	// update params
	params.Name = accountName
	params.NKeyID = data.Get(cmdAccountFieldParams[AccountNKeyID]).(string)
	params.TokenClaims.Limits.Subs = int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsSubs]).(int))
	params.TokenClaims.Limits.Data = int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsData]).(int))
	params.TokenClaims.Limits.Payload = int64(data.Get(cmdAccountFieldParams[AccountLimitsNatsPayload]).(int))

	params.TokenClaims.Limits.Conn = int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountConn]).(int))
	params.TokenClaims.Limits.LeafNodeConn = int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountLeafNodeConn]).(int))
	params.TokenClaims.Limits.Imports = int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountImports]).(int))
	params.TokenClaims.Limits.Exports = int64(data.Get(cmdAccountFieldParams[AccountLimitsAccountExports]).(int))
	params.TokenClaims.Limits.WildcardExports = data.Get(cmdAccountFieldParams[AccountLimitsAccountWildcardExports]).(bool)

	params.TokenClaims.Limits.MemoryStorage = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMemStorage]).(int))
	params.TokenClaims.Limits.DiskStorage = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamDiskStorage]).(int))
	params.TokenClaims.Limits.Streams = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamStreams]).(int))
	params.TokenClaims.Limits.Consumer = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamConsumer]).(int))
	params.TokenClaims.Limits.MaxAckPending = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMaxAckPending]).(int))
	params.TokenClaims.Limits.MemoryMaxStreamBytes = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMemoryMaxStreamBytes]).(int))
	params.TokenClaims.Limits.DiskMaxStreamBytes = int64(data.Get(cmdAccountFieldParams[AccountLimitsJetstreamDiskMaxStreamBytes]).(int))
	params.TokenClaims.Limits.MaxBytesRequired = data.Get(cmdAccountFieldParams[AccountLimitsJetstreamMaxBytesRequired]).(bool)
	params.TokenClaims.Subject = converted.PublicKey
	params.TokenClaims.Name = accountName

	err = updateAccountJwt(ctx, req.Storage, params, convertedSigningKey.KeyPair, accountName)
	if err != nil {
		return nil, err
	}

	// store operator parameters
	_, err = storeInStorage(ctx, req.Storage, accountCmdPath(accountName), params)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *NatsBackend) pathReadAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(data.Get("name").(string)))
}

func (b *NatsBackend) pathDeleteAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, accountCmdPath(data.Get("name").(string)))
	if err != nil {
		return nil, fmt.Errorf("error deleting account: %w", err)
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
		return nil, fmt.Errorf("missing account")
	}
	return params, nil
}
