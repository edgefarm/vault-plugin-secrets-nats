package natsbackend

import (
	"context"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/validate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

const (
	UserName validate.Key = iota
	UserAccountName
	UserAccountSigningKey
	UserNKeyID
)

var (
	cmdUserFieldParams = map[validate.Key]string{
		UserName:              "name",
		UserNKeyID:            "nkey_id",
		UserAccountName:       "account_name",
		UserAccountSigningKey: "account_signing_key",
	}

	validPathCmdUserFields []string = []string{
		cmdOperatorFieldParams[UserName],
		cmdOperatorFieldParams[UserNKeyID],
		cmdOperatorFieldParams[UserAccountName],
		cmdOperatorFieldParams[UserAccountSigningKey],
	}
)

func pathCmdUser(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			cmdOperatorFieldParams[UserName]: {
				Type:        framework.TypeString,
				Description: "User Name",
				Required:    true,
			},
			cmdOperatorFieldParams[UserNKeyID]: {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id",
				Required:    false,
				Default:     "",
			},
			cmdOperatorFieldParams[UserAccountName]: {
				Type:        framework.TypeString,
				Description: "Account Name",
				Required:    true,
			},
			cmdOperatorFieldParams[UserAccountSigningKey]: {
				Type:        framework.TypeString,
				Description: "Account Signing Key",
				Required:    false,
				Default:     "",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathAddUserCmd,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAddUserCmd,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadUserCmd,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteUserCmd,
			},
		},
		HelpSynopsis:    `Manages user cmd's.`,
		HelpDescription: ``,
	}
}

type UserConfig struct {
	Name        string `json:"name"`
	AccountName string `json:"account_name"`
	NKeyID      string `json:"nkey_id"`
}

func (b *NatsBackend) pathAddUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := validate.ValidateFields(data.Raw, validPathCmdUserFields); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	config := &UserConfig{
		Name:        data.Get(cmdOperatorFieldParams[UserName]).(string),
		AccountName: data.Get(cmdOperatorFieldParams[UserAccountName]).(string),
		NKeyID:      data.Get(cmdOperatorFieldParams[UserNKeyID]).(string),
	}
	accountSigningKey := data.Get(cmdOperatorFieldParams[UserAccountSigningKey]).(string)

	accountParams, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(config.AccountName))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if accountParams == nil {
		return logical.ErrorResponse(AccountNotFoundError), nil
	}

	// Signing key isn't provided, so choose account key as signing key
	var signingKey *Nkey
	if accountSigningKey == "" {
		nkey, err := getNkey(ctx, req.Storage, User, config.NKeyID)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if nkey == nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		signingKey = nkey
	} else {
		// Signing key is provided, so validate it that is a valid signing key for the account
		// receive nkey data structure from storage
		nkey, err := getNkey(ctx, req.Storage, Account, config.AccountName)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if nkey == nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if accountParams.TokenClaims.Account.SigningKeys != nil {
			for _, signingKey := range accountParams.TokenClaims.Account.SigningKeys {
				converted, err := convertSeed(nkey.Seed)
				if err != nil {
					return logical.ErrorResponse(err.Error()), nil
				}
				if nkey.

		signingKey = nkey
	}

	err = b.AddUserCmd(ctx, req.Storage, config, signingKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

}

func (b *NatsBackend) AddUserCmd(ctx context.Context, s logical.Storage, config *UserConfig, signingKey *Nkey) error {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return logical.ErrorResponse(JwtMissingAccountNameError), nil
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return logical.ErrorResponse(JwtMissingUserNameError), nil
	}

	// get Operator storage
	user, err := getFromStorage[Parameters[jwt.UserClaims]](ctx, req.Storage, userCmdPath(account, name))
	if err != nil {
		return logical.ErrorResponse(JwtUserNotFound), err
	}

	// no storage exists, create new
	if user == nil {
		user = &Parameters[jwt.UserClaims]{}
	}

	// set the values
	user.NKeyID = data.Get("NKeyID").(string)

	return nil, nil
}

func (b *NatsBackend) pathReadUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing account name"), nil
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return logical.ErrorResponse("missing user name"), nil
	}

	return readOperation[Parameters[jwt.UserClaims]](ctx, req.Storage, userJwtPath(account, name))
}

func (b *NatsBackend) pathDeleteUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, userCmdPath(data.Get("account").(string), data.Get("name").(string)))
	if err != nil {
		return logical.ErrorResponse("error deleting user: %w", err), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathCmdUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accountName := d.Get("account_name").(string)
	entries, err := req.Storage.List(ctx, "cmd/operator/account/"+accountName+"/user")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(entries), nil
}
