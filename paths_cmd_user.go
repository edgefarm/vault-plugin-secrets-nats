package natsbackend

import (
	"context"
	"errors"
	"fmt"

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
		cmdUserFieldParams[UserName],
		cmdUserFieldParams[UserNKeyID],
		cmdUserFieldParams[UserAccountName],
		cmdUserFieldParams[UserAccountSigningKey],
	}
)

func pathCmdUser(b *NatsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cmd/operator/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			cmdUserFieldParams[UserName]: {
				Type:        framework.TypeString,
				Description: "User Name",
				Required:    true,
			},
			cmdUserFieldParams[UserNKeyID]: {
				Type:        framework.TypeString,
				Description: "Create or use existing NKey with this id",
				Required:    false,
				Default:     "",
			},
			cmdUserFieldParams[UserAccountName]: {
				Type:        framework.TypeString,
				Description: "Account Name",
				Required:    true,
			},
			cmdUserFieldParams[UserAccountSigningKey]: {
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
	UserPath    string `json:"user_path"`
}

func (b *NatsBackend) pathAddUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := validate.ValidateFields(data.Raw, validPathCmdUserFields); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var account string
	if accountParam, ok := data.GetOk(cmdUserFieldParams[UserAccountName]); ok {
		account = accountParam.(string)
	} else if !ok {
		return logical.ErrorResponse(JwtMissingAccountNameError), nil
	}

	var name string
	if nameParam, ok := data.GetOk(cmdUserFieldParams[UserName]); ok {
		name = nameParam.(string)
	} else if !ok {
		return logical.ErrorResponse(JwtMissingUserNameError), nil
	}

	config := &UserConfig{
		AccountName: account,
		Name:        name,
		NKeyID:      data.Get(cmdUserFieldParams[UserNKeyID]).(string),
		UserPath:    userCmdPath(account, name),
	}

	if config.NKeyID == "" {
		config.NKeyID = fmt.Sprintf("%s_%s", config.AccountName, config.Name)
	}

	accountSigningKey := data.Get(cmdUserFieldParams[UserAccountSigningKey]).(string)

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
		nkey, err := getNkey(ctx, req.Storage, Account, accountParams.NKeyID)
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
		nkey, err := getNkey(ctx, req.Storage, Account, accountSigningKey)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if nkey == nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		converted, err := convertSeed(nkey.Seed)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if accountParams.TokenClaims.Account.SigningKeys != nil {
			if _, ok := accountParams.TokenClaims.Account.SigningKeys[converted.PublicKey]; ok {
				signingKey = nkey
			}
		}
	}

	err = b.AddUserCmd(ctx, req.Storage, config, signingKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

func (b *NatsBackend) AddUserCmd(ctx context.Context, s logical.Storage, c *UserConfig, signingKey *Nkey) error {

	// get Users storage
	user, err := getFromStorage[Parameters[jwt.UserClaims]](ctx, s, c.UserPath)
	if err != nil {
		return errors.New(JwtUserNotFound)
	}

	// no storage exists, create new
	if user == nil {
		user = &Parameters[jwt.UserClaims]{}
	}

	// create user nkey
	userKey, err := getNkey(ctx, s, User, c.NKeyID)
	if err != nil {
		return errors.New(NKeyStorageAccessError)
	}
	if userKey == nil {
		userKey, err = createNkey(ctx, s, User, c.NKeyID)
		if err != nil {
			return err
		}
	}

	// convert signing key
	convertedSigningKey, err := convertSeed(signingKey.Seed)
	if err != nil {
		return err
	}

	// convert account key
	convertedUserKey, err := convertSeed(userKey.Seed)
	if err != nil {
		return err
	}

	accountNkey, err := getNkey(ctx, s, Account, c.AccountName)
	if err != nil {
		return err
	}

	if accountNkey == nil {
		return err
	}
	convertedAccountKey, err := convertSeed(accountNkey.Seed)
	if err != nil {
		return err
	}

	// set the values
	user.Name = c.Name
	user.NKeyID = c.NKeyID
	user.TokenID = c.Name
	user.TokenClaims.IssuerAccount = convertedAccountKey.PublicKey
	user.TokenClaims.Issuer = convertedSigningKey.PublicKey
	user.TokenClaims.Subject = convertedUserKey.PublicKey

	// store operator parameters
	_, err = storeInStorage(ctx, s, c.UserPath, user)
	if err != nil {
		return err
	}

	return nil
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

	// path := userCmdPath(account, name)
	// param, err := getFromStorage[Parameters[jwt.UserClaims]](ctx, req.Storage, path)
	// if err != nil {
	// 	return logical.ErrorResponse(err.Error()), nil
	// }
	// if param == nil {
	// 	return logical.ErrorResponse("user not found"), nil
	// }

	// var groupMap map[string]interface{}

	// err = mapstructure.Decode(param, &groupMap)
	// if err != nil {
	// 	return nil, err
	// }

	// return &logical.Response{
	// 	Data: groupMap,
	// }, nil
	return readOperation[Parameters[jwt.UserClaims]](ctx, req.Storage, userCmdPath(account, name))
}

func (b *NatsBackend) pathDeleteUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, userCmdPath(data.Get("account").(string), data.Get("name").(string)))
	if err != nil {
		return logical.ErrorResponse("error deleting user: %w", err), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathCmdUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// accountName := d.Get("account_name").(string)
	// entries, err := req.Storage.List(ctx, accountCmdPath(accountName)+"/user")
	entries, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return logical.ListResponse(entries), nil
}
