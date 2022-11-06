package natsbackend

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/nats-io/nkeys"
)

// Nkey represens a named NKey keypair.
type Nkey struct {
	Name string `json:"name" mapstructure:"name"`
	KeyPair
}

// keyPair represens a nkey seed, which can be used to generate a public key and private key.
type KeyPair struct {
	Seed string `json:"seed" mapstructure:"seed"`
}

// getPrefixByte is a helper function to get the prefix byte for a given category.
func getPrefixByte(category string) (nkeys.PrefixByte, error) {
	switch {
	case category == "operator":
		return nkeys.PrefixByteOperator, nil
	case category == "account":
		return nkeys.PrefixByteAccount, nil
	case category == "user":
		return nkeys.PrefixByteUser, nil
	default:
		return 0, fmt.Errorf("unknown nkey category: %s", category)
	}
}

// getNkeyPath is a helper function to get the path for a given category and name.
func getNkeyPath(category string, name string) string {
	return "nkey/" + category + "/" + name
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
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed - Base64 Encoded.",
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
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed - Base64 Encoded.",
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
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed - Base64 Encoded.",
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
	return b.pathAddNkey(ctx, req, data, "operator")
}

func (b *NatsBackend) pathAddAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "account")
}

func (b *NatsBackend) pathAddUserNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathAddNkey(ctx, req, data, "user")
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

	// receive nkey data structure from storage
	nkey, err := getNkey(ctx, req.Storage, category, data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if nkey == nil {
		return nil, nil
	}

	// convert seed into public/private key data structure
	result, err := convertSeed(nkey.Seed)
	if err != nil {
		return nil, err
	}
	// add name to data structure
	result["name"] = nkey.Name

	// return data structure
	return &logical.Response{
		Data: result,
	}, nil
}

func (b *NatsBackend) pathAddNkey(ctx context.Context, req *logical.Request, data *framework.FieldData, category string) (*logical.Response, error) {
	// readout fields
	name := data.Get("name").(string)
	seed := data.Get("seed").(string)

	// when no seed is given, generate a new one
	if seed == "" {
		_, err := createNkey(ctx, req.Storage, category, name)
		return nil, err
	}

	// when a key is given, store it
	err := addNkey(ctx, req.Storage, category, name, seed)
	return nil, err
}

func addNkey(ctx context.Context, s logical.Storage, category string, name string, seed string) error {
	// get Nkey storage
	nkey, err := getNkey(ctx, s, category, name)
	if err != nil {
		return fmt.Errorf("missing peer")
	}

	// no storage exists, create new
	if nkey == nil {
		nkey = &Nkey{}
	}

	// save modifications to storage
	nkey.Name = name
	nkey.Seed = seed
	if _, err := storeInStorage(ctx, s, getNkeyPath(category, name), nkey); err != nil {
		return err
	}
	return nil
}

// createKeyPair creates a new Nkey keypair with name
func createNkey(ctx context.Context, s logical.Storage, category string, name string) (*Nkey, error) {

	// map category to prefix
	prefix, err := getPrefixByte(category)
	if err != nil {
		return nil, err
	}

	// create a new Nkey keypair
	kp, err := createKeyPair(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// save modifications to storage
	nkey := &Nkey{}
	nkey.Name = name
	nkey.Seed = kp.Seed
	if _, err := storeInStorage(ctx, s, getNkeyPath(category, name), nkey); err != nil {
		return nil, err
	}
	return nkey, nil
}

// createKeyPair creates a new Nkey keypair
func createKeyPair(ctx context.Context, prefix nkeys.PrefixByte) (*KeyPair, error) {

	var kp KeyPair

	// create operator keypair
	keypair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, err
	}

	// store seed
	seed, err := keypair.Seed()
	if err != nil {
		return nil, err
	}
	kp.Seed = base64.StdEncoding.EncodeToString(seed)

	return &kp, nil
}

// getNkey returns the Nkey object for the given name and category
func getNkey(ctx context.Context, s logical.Storage, category, name string) (*Nkey, error) {

	if category == "" {
		return nil, fmt.Errorf("missing nkey category name (`operator`,`account`,`user`")
	}

	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	return getFromStorage[Nkey](ctx, s, getNkeyPath(category, name))
}

// convertSeed converts a seed from a string to a map with publickey and private key.
func convertSeed(seed string) (map[string]interface{}, error) {

	s, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, err
	}

	nk, err := nkeys.FromSeed(s)
	if err != nil {
		return nil, err
	}

	public, err := nk.PublicKey()
	if err != nil {
		return nil, err
	}

	private, err := nk.PrivateKey()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"public_key":  public,
		"private_key": base64.StdEncoding.EncodeToString(private),
		"seed":        seed,
	}, nil
}
