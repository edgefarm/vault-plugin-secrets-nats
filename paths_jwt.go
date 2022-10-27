package natsbackend

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
)

type JwtToken struct {
	Jwt string `json:"jwt" mapstructure:"jwt"`
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
			},
			HelpSynopsis:    `Manages user JWT's.`,
			HelpDescription: ``,
		},
	}
}

func (b *NatsBackend) pathAddOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return addJWT[jwt.OperatorClaims](ctx, req, data, "/nkey/operator")
}

func (b *NatsBackend) pathAddAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	return addJWT[jwt.AccountClaims](ctx, req, data, "/nkey/operator/"+name)
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

	return addJWT[jwt.UserClaims](ctx, req, data, "/nkey/operator/"+account+"/"+name)
}

func (b *NatsBackend) pathReadOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return readJWT(ctx, req, data, "/nkey/operator")
}

func (b *NatsBackend) pathReadAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var name string
	if nameParam, ok := data.GetOk("name"); ok {
		name = nameParam.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing account name")
	}

	return readJWT(ctx, req, data, "/nkey/operator/"+name)
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

	return readJWT(ctx, req, data, "/nkey/operator/"+account+"/"+name)
}

func readJWT(ctx context.Context, req *logical.Request, data *framework.FieldData, path string) (*logical.Response, error) {
	jwtToken, err := getJWT(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}

	if jwtToken == nil {
		return nil, nil
	}

	var groupMap map[string]interface{}

	err = mapstructure.Decode(jwtToken, &groupMap)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: groupMap,
	}, nil
}

func addJWT[T any, P interface{ *T }](ctx context.Context, req *logical.Request, data *framework.FieldData, path string) (*logical.Response, error) {
	tokenParam, ok := data.GetOk("jwt")
	if !ok {
		return nil, fmt.Errorf("missing jwt token")
	}

	claims, err := jwt.Decode(tokenParam.(string))
	if err != nil {
		return nil, err
	}
	_, ok = claims.(P)
	if !ok {
		return nil, errors.New("token has wrong claim type")
	}

	var token JwtToken
	token.Jwt = tokenParam.(string)
	entry, err := logical.StorageEntryJSON(path, token)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func getJWT(ctx context.Context, s logical.Storage, path string) (*JwtToken, error) {

	if path == "" {
		return nil, fmt.Errorf("missing path")
	}

	// get jwt from storage backend
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("error retrieving JWT: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// convert json data to T
	var token JwtToken
	if err := entry.DecodeJSON(&token); err != nil {
		return nil, fmt.Errorf("error decoding JWT data: %w", err)
	}
	return &token, nil
}
