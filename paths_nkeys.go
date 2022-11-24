package natsbackend

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/nats-io/nkeys"
)

type Category int

const (
	Operator Category = iota
	Account
	User
)

var (
	CategoryMap = map[Category]string{
		Operator: "operator",
		Account:  "account",
		User:     "user",
	}
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
func getPrefixByte(c Category) (nkeys.PrefixByte, error) {
	switch {
	case c == Operator:
		return nkeys.PrefixByteOperator, nil
	case c == Account:
		return nkeys.PrefixByteAccount, nil
	case c == User:
		return nkeys.PrefixByteUser, nil
	default:
		return 0, fmt.Errorf("unknown nkey category")
	}
}

// getNkeyPath is a helper function to get the path for a given category and name.
func getNkeyPath(c Category, name string) string {
	return "nkey/" + CategoryMap[c] + "/" + name
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

func (b *NatsBackend) pathReadNkey(ctx context.Context, req *logical.Request, data *framework.FieldData, c Category) (*logical.Response, error) {

	// receive nkey data structure from storage
	nkey, err := getNkey(ctx, req.Storage, c, data.Get("name").(string))
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

func (b *NatsBackend) pathAddNkey(ctx context.Context, req *logical.Request, data *framework.FieldData, c Category) (*logical.Response, error) {
	// readout fields
	name := data.Get("name").(string)
	seed := data.Get("seed").(string)

	// when no seed is given, generate a new one
	if seed == "" {
		_, err := createNkey(ctx, req.Storage, c, name)
		return nil, err
	}

	// when a key is given, store it
	err := addNkey(ctx, req.Storage, c, name, seed)
	return nil, err
}

func addNkey(ctx context.Context, s logical.Storage, c Category, name string, seed string) error {
	// get Nkey storage
	nkey, err := getNkey(ctx, s, c, name)
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
	if _, err := storeInStorage(ctx, s, getNkeyPath(c, name), nkey); err != nil {
		return err
	}
	return nil
}

// createKeyPair creates a new Nkey keypair with name
func createNkey(ctx context.Context, s logical.Storage, c Category, name string) (*Nkey, error) {

	// map category to prefix
	prefix, err := getPrefixByte(c)
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
	if _, err := storeInStorage(ctx, s, getNkeyPath(c, name), nkey); err != nil {
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
func getNkey(ctx context.Context, s logical.Storage, c Category, name string) (*Nkey, error) {

	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	return getFromStorage[Nkey](ctx, s, getNkeyPath(c, name))
}

func deleteNKey(ctx context.Context, s logical.Storage, c Category, name string) error {
	return deleteFromStorage(ctx, s, getNkeyPath(c, name))
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
