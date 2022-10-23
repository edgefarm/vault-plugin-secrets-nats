package natsbackend

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"

	"github.com/nats-io/nkeys"
)

// Nkey represens a named nkey public key private key pair.
type Nkey struct {
	Name string `json:"name" mapstructure:"name"`
	KeyPair
}

// keyPair represens a nkey public key private key pair
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// pathNkey extends the Vault API with a `/nkey/<category>`
// endpoint for the natsBackend.
func pathNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the Nkey.",
					Required:    false,
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Nkey private key - Base64 Encoded.",
					Required:    false,
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "Nkey public key.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorNkey,
				},
			},
			HelpSynopsis:    `Manages operator Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no operator Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/account/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the Nkey.",
					Required:    false,
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Nkey private key - Base64 Encoded.",
					Required:    false,
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "Nkey public key.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountNkey,
				},
			},
			HelpSynopsis:    `Manages account Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no account Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/user/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the Nkey.",
					Required:    false,
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Nkey private key - Base64 Encoded.",
					Required:    false,
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "Nkey public key.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserNkey,
				},
			},
			HelpSynopsis:    `Manages user Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no user Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
	}
}

func (b *NatsBackend) pathAddOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "operator", nkeys.PrefixByteOperator)
}

func (b *NatsBackend) pathAddAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "account", nkeys.PrefixByteAccount)
}

func (b *NatsBackend) pathAddUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "user", nkeys.PrefixByteUser)
}

func (b *NatsBackend) pathReadOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, "operator")
}

func (b *NatsBackend) pathReadAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, "account")
}

func (b *NatsBackend) pathReadUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathReadNkey(ctx, req, data, "user")
}

func (b *NatsBackend) pathReadNkey(ctx context.Context, req *logical.Request, data *framework.FieldData, category string) (*logical.Response, error) {
	nkey, err := getNkey(ctx, req.Storage, category, data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if nkey == nil {
		return nil, nil
	}

	var groupMap map[string]interface{}

	err = mapstructure.Decode(nkey, &groupMap)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: groupMap,
	}, nil
}

func (b *NatsBackend) pathAddNkey(ctx context.Context, req *logical.Request, data *framework.FieldData, category string, prefix nkeys.PrefixByte) (*logical.Response, error) {

	name := data.Get("name").(string)
	privateKey := data.Get("private_key").(string)
	publicKey := data.Get("public_key").(string)

	if publicKey == "" && privateKey != "" {
		return logical.ErrorResponse("private key without public key"), nil
	}

	// when no key is given, generate a new one
	if privateKey == "" && publicKey == "" {

		kp, err := generateNkey(ctx, nkeys.PrefixByteOperator)
		if err != nil {
			return nil, err
		}

		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	}

	// when no name is given, use publicKey
	if name == "" {
		name = publicKey
	}

	// get Nkey storage
	nkey, err := getNkey(ctx, req.Storage, category, name)
	if err != nil {
		return logical.ErrorResponse("missing peer"), err
	}

	// no storage exists, create new
	if nkey == nil {
		nkey = &Nkey{}
	}

	// save modifications to storage
	nkey.Name = name
	nkey.PrivateKey = privateKey
	nkey.PublicKey = publicKey
	if err := b.put(ctx, req.Storage, "nkey/"+category+"/"+name, nkey); err != nil {
		return nil, err
	}
	return nil, nil
}

func generateNkey(ctx context.Context, prefix nkeys.PrefixByte) (*KeyPair, error) {

	var kp KeyPair

	// create operator keypair
	keypair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, err
	}

	// store public key
	kp.PublicKey, err = keypair.PublicKey()
	if err != nil {
		return nil, err
	}

	// store private key
	var pKey []byte
	pKey, err = keypair.PrivateKey()
	if err != nil {
		return nil, err
	}
	kp.PrivateKey = base64.StdEncoding.EncodeToString(pKey)

	return &kp, nil
}

func getNkey(ctx context.Context, s logical.Storage, category, name string) (*Nkey, error) {

	if category == "" {
		return nil, fmt.Errorf("missing nkey category name (`operator`,`account`,`user`")
	}

	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	// get nkey from storage backend
	entry, err := s.Get(ctx, "nkey/"+category+"/"+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving peer: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// convert nkey to json and return
	var nkey Nkey
	if err := entry.DecodeJSON(&nkey); err != nil {
		return nil, fmt.Errorf("error decoding Nkey data: %w", err)
	}
	return &nkey, nil
}
