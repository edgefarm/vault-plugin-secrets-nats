package natsbackend

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

type JwtToken struct {
	Jwt string `json:"jwt" mapstructure:"jwt"`
}

func operatorJwtPath() string {
	return "jwt/operator"
}

func accountJwtPath(account string) string {
	return "jwt/operator/account/" + account
}

func userJwtPath(account, user string) string {
	return "jwt/operator/account" + account + "/user/" + user
}

// pathJWT extends the Vault API with a `/jwt/<category>`
// endpoint for the natsBackend.
func pathJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator",
			Fields: map[string]*framework.FieldSchema{
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
			},
			ExistenceCheck:  b.pathJwtExistenceCheck,
			HelpSynopsis:    `Manages operator JWT.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/account/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Account Name.",
					Required:    false,
				},
				"jwt": {
					Type:        framework.TypeString,
					Description: "Account JWT to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountJWT,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountJWT,
				},
			},
			HelpSynopsis:    `Manages account JWT's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/account/" + framework.GenericNameRegex("account_name") + "/user/" + framework.GenericNameRegex("name") + "$",
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
				"jwt": {
					Type:        framework.TypeString,
					Description: "User JWT to import.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserJWT,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListUserJWT,
				},
			},
			HelpSynopsis:    `Manages user JWT's.`,
			HelpDescription: ``,
		},
	}
}

func (b *NatsBackend) pathJwtExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *NatsBackend) pathAddOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var token string
	if tokenParam, ok := data.GetOk("jwt"); ok {
		token = tokenParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing user name")
	}
	return nil, addOperatorJWT(ctx, req.Storage, token)
}

func (b *NatsBackend) pathAddAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	var token string
	if tokenParam, ok := data.GetOk("jwt"); ok {
		token = tokenParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing user name")
	}

	return nil, addAccountJWT(ctx, req.Storage, token, name)
}

func (b *NatsBackend) pathAddUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	var token string
	if tokenParam, ok := data.GetOk("jwt"); ok {
		token = tokenParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing user name")
	}

	return nil, addUserJWT(ctx, req.Storage, token, account, name)
}

func (b *NatsBackend) pathReadOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readOperation[JwtToken](ctx, req.Storage, operatorJwtPath())
}

func (b *NatsBackend) pathReadAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	return readOperation[JwtToken](ctx, req.Storage, accountJwtPath(name))
}

func (b *NatsBackend) pathListAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "jwt/operator/account/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathReadUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	return readOperation[JwtToken](ctx, req.Storage, userJwtPath(account, name))
}

func (b *NatsBackend) pathListUserJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var account string
	if accountParam, ok := data.GetOk("account_name"); ok {
		account = accountParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	entries, err := req.Storage.List(ctx, "jwt/operator/account/"+account+"/user/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func addOperatorJWT(ctx context.Context, s logical.Storage, token string) error {
	return addJWT[jwt.OperatorClaims](ctx, s, token, operatorJwtPath())
}

func addAccountJWT(ctx context.Context, s logical.Storage, token string, account string) error {
	return addJWT[jwt.AccountClaims](ctx, s, token, accountJwtPath(account))
}

func addUserJWT(ctx context.Context, s logical.Storage, token string, account string, user string) error {
	return addJWT[jwt.UserClaims](ctx, s, token, userJwtPath(account, user))
}

func addJWT[T any, P interface{ *T }](ctx context.Context, s logical.Storage, token string, path string) error {
	claims, err := jwt.Decode(token)
	if err != nil {
		return err
	}
	_, ok := claims.(P)
	if !ok {
		return errors.New("token has wrong claim type")
	}

	t := &JwtToken{}
	t.Jwt = token
	if _, err := storeInStorage(ctx, s, path, t); err != nil {
		return err
	}
	return nil
}
