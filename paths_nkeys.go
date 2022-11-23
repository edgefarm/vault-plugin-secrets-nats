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
	Seed string `json:"seed" mapstructure:"seed"`
}

// // keyPair represens a nkey seed, which can be used to generate a public key and private key.
// type KeyPair struct {

// }

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
		pathOperatorNkey(b),
		pathUserNkey(b),
		pathAccountNkey(b),
		{
			Pattern: "nkey/operator/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathOperatorNkeysList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
		{
			Pattern: "nkey/account/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountNkeysList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
		{
			Pattern: "nkey/user/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathUserNkeysList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
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
	converted, err := convertSeed(nkey.Seed)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"public_key":  converted.PublicKey,
		"private_key": converted.PrivateKey,
		"seed":        converted.Seed,
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

	// create a new Nkey seed
	seed, err := createSeed(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// save modifications to storage
	nkey := &Nkey{}
	nkey.Name = name
	nkey.Seed = seed
	if _, err := storeInStorage(ctx, s, getNkeyPath(category, name), nkey); err != nil {
		return nil, err
	}
	return nkey, nil
}

// createKeyPair creates a new Nkey keypair
func createSeed(ctx context.Context, prefix nkeys.PrefixByte) (string, error) {

	// create operator keypair
	keypair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return "", err
	}

	// store seed
	seed, err := keypair.Seed()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
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

func deleteNKey(ctx context.Context, s logical.Storage, category string, name string) error {
	return deleteFromStorage(ctx, s, getNkeyPath(category, name))
}

type NkeyInfo struct {
	PublicKey  string
	PrivateKey string
	Seed       string
	KeyPair    nkeys.KeyPair
}

// convertSeed converts a seed from a string to a map with publickey and private key.
func convertSeed(seed string) (*NkeyInfo, error) {

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

	return &NkeyInfo{
		PublicKey:  public,
		PrivateKey: base64.StdEncoding.EncodeToString(private),
		Seed:       seed,
		KeyPair:    nk,
	}, nil
}
