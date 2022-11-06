package natsbackend

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type Parameters[T any] struct {
	Name        string `json:"name" mapstructure:"name"`
	TokenClaims T      `json:"claims" mapstructure:"claims"`
	TokenID     string `json:"token_id" mapstructure:"token_id"`
	NKeyID      string `json:"nkey_id" mapstructure:"nkey_id"`
}

func operatorCmdPath() string {
	return "cmd/operator"
}

func accountCmdPath(account string) string {
	return "cmd/operator/" + account
}

func userCmdPath(account, user string) string {
	return "cmd/operator/" + account + "/" + user
}

// pathCmd extends the Vault API with a `/cmd/<category>`
// endpoint for the natsBackend.
func pathCmd(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "cmd/operator",
			Fields: map[string]*framework.FieldSchema{
				"NKeyID": {
					Type:        framework.TypeString,
					Description: "Create or use existing NKey with this id.",
					Required:    false,
				},
				"SigningKeys": {
					Type:        framework.TypeStringSlice,
					Description: "Slice of other operator NKeys IDs that can be used to sign on behalf of the main operator identity.",
					Required:    false,
				},
				"StrictSigningKeyUsage": {
					Type:        framework.TypeBool,
					Description: "Signing of subordinate objects will require signing keys.",
					Required:    false,
				},
				"AccountServerURL": {
					Type:        framework.TypeString,
					Description: "Account Server URL for pushing jwt's.",
					Required:    false,
				},
				"SystemAccount": {
					Type:        framework.TypeString,
					Description: "Operator NKeys path of the system account.",
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
			},
			HelpSynopsis:    `Manages operator Cmd.`,
			HelpDescription: ``,
		},
		{
			Pattern: "cmd/operator/account/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Account Name.",
					Required:    false,
				},
				"NKeyID": {
					Type:        framework.TypeString,
					Description: "Create or use existing NKey with this id.",
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
			},
			HelpSynopsis:    `Manages account Cmd's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "cmd/operator/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "User Name.",
					Required:    false,
				},
				"account_name": {
					Type:        framework.TypeString,
					Description: "Account Name.",
					Required:    false,
				},
				"NKeyID": {
					Type:        framework.TypeString,
					Description: "Create or use existing NKey with this id.",
					Required:    false,
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
			},
			HelpSynopsis:    `Manages user Cmd's.`,
			HelpDescription: ``,
		},
	}
}

func (b *NatsBackend) pathAddOperatorCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get Operator storage
	operator, err := getFromStorage[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
	if err != nil {
		return logical.ErrorResponse("missing operator"), err
	}

	// no storage exists, create new
	if operator == nil {
		operator = &Parameters[jwt.OperatorClaims]{}
	}

	// set the values
	operator.NKeyID = data.Get("NKeyID").(string)
	operator.TokenClaims.SigningKeys = data.Get("SigningKeys").([]string)
	operator.TokenClaims.StrictSigningKeyUsage = data.Get("StrictSigningKeyUsage").(bool)
	operator.TokenClaims.AccountServerURL = data.Get("AccountServerURL").(string)
	operator.TokenClaims.SystemAccount = data.Get("SystemAccount").(string)

	// create operator nkey
	okey, err := getNkey(ctx, req.Storage, "operator", operator.NKeyID)
	if err != nil {
		return logical.ErrorResponse("error while accessing nkey storage"), err
	}
	if okey == nil {
		okey, err = createNkey(ctx, req.Storage, "operator", operator.NKeyID)
		if err != nil {
			return nil, err
		}
	}
	oseed, err := base64.StdEncoding.DecodeString(okey.Seed)
	if err != nil {
		return nil, err
	}
	onk, err := nkeys.FromSeed(oseed)
	if err != nil {
		return nil, err
	}
	opubKey, err := onk.PublicKey()
	if err != nil {
		return nil, err
	}
	operator.TokenClaims.Subject = opubKey

	// create operator jwt
	token, err := getFromStorage[JwtToken](ctx, req.Storage, operatorJwtPath())
	if err != nil {
		return nil, err
	}
	if token == nil {
		token = &JwtToken{}

		// create operator jwt
		token.Jwt, err = operator.TokenClaims.Encode(onk)
		if err != nil {
			return nil, err
		}

		err = addOperatorJWT(ctx, req.Storage, token.Jwt)
		if err != nil {
			return nil, err
		}
	}

	// create siging keys
	skey := okey
	sseed, err := base64.StdEncoding.DecodeString(okey.Seed)
	if err != nil {
		return nil, err
	}
	_, err = nkeys.FromSeed(sseed)
	if err != nil {
		return nil, err
	}
	for _, key := range operator.TokenClaims.SigningKeys {
		// get signing key
		skey, err = getNkey(ctx, req.Storage, "operator", key)
		if err != nil {
			return logical.ErrorResponse("error while accessing nkey storage"), err
		}
		// create signing key if it doesn't exist
		if skey == nil {
			skey, err = createNkey(ctx, req.Storage, "operator", key)
			if err != nil {
				return nil, err
			}
		}
	}

	// check system account
	// if operator.TokenClaims.SystemAccount != "" {
	// 	// get system account
	// 	sa, err := getNkey(ctx, req.Storage, "account", operator.TokenClaims.SystemAccount)
	// 	if err != nil {
	// 		return logical.ErrorResponse("error while accessing nkey storage"), err
	// 	}

	// 	// create system account
	// 	if sa == nil {
	// 		sa, err = createNkey(ctx, req.Storage, "account", operator.TokenClaims.SystemAccount)
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 	}

	// 	// get system account user
	// 	sau, err := getNkey(ctx, req.Storage, "user", operator.TokenClaims.SystemAccount)
	// 	if err != nil {
	// 		return logical.ErrorResponse("error while accessing nkey storage"), err
	// 	}

	// 	// create system account user
	// 	if sau == nil {
	// 		sau, err = createNkey(ctx, req.Storage, "user", operator.TokenClaims.SystemAccount)
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 	}
	// }

	return nil, nil
}

func (b *NatsBackend) pathAddAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	// get account storage
	account, err := getFromStorage[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(name))
	if err != nil {
		return logical.ErrorResponse("missing account"), err
	}

	// no storage exists, create new
	if account == nil {
		account = &Parameters[jwt.AccountClaims]{}
	}

	// set the values
	account.NKeyID = data.Get("NKeyID").(string)
	//account.TokenClaims.SigningKeys = data.Get("SigningKeys").([]string)

	return nil, nil
}

func (b *NatsBackend) pathAddUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing user name")
	}

	// get Operator storage
	user, err := getFromStorage[Parameters[jwt.UserClaims]](ctx, req.Storage, userCmdPath(account, name))
	if err != nil {
		return logical.ErrorResponse("missing user"), err
	}

	// no storage exists, create new
	if user == nil {
		user = &Parameters[jwt.UserClaims]{}
	}

	// set the values
	user.NKeyID = data.Get("NKeyID").(string)

	return nil, nil
}

func (b *NatsBackend) pathReadOperatorCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[Parameters[jwt.OperatorClaims]](ctx, req.Storage, operatorCmdPath())
}

func (b *NatsBackend) pathReadAccountCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	return readOperation[Parameters[jwt.AccountClaims]](ctx, req.Storage, accountCmdPath(name))
}

func (b *NatsBackend) pathReadUserCmd(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing user name")
	}

	return readOperation[Parameters[jwt.UserClaims]](ctx, req.Storage, userJwtPath(account, name))
}
