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

// NkeySorage represents a Nkey stored in the backend
type NKeyStorage struct {
	Seed string `mapstructure:"seed,omitempty"`
}

// NkeyParameters represents the parameters for a Nkey operation
type NkeyParameters struct {
	Operator    string `mapstructure:"operator,omitempty"`
	Signing     string `mapstructure:"signing,omitempty"`
	Account     string `mapstructure:"account,omitempty"`
	User        string `mapstructure:"user,omitempty"`
	NKeyStorage `mapstructure:",squash"`
}

// NkeyData represents the the data returned by a Nkey operation
type NkeyData struct {
	NKeyStorage `mapstructure:",squash"`
	PublicKey   string `mapstructure:"public_key,omitempty"`
	PrivateKey  string `mapstructure:"private_key,omitempty"`
}

// pathNkey extends the Vault API with a `/nkey/<category>`
// endpoint for the natsBackend.
func pathNkey(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorNkey(b)...)
	paths = append(paths, pathOperatorSigningNkey(b)...)
	paths = append(paths, pathAccountNkey(b)...)
	paths = append(paths, pathAccountSigningNkey(b)...)
	paths = append(paths, pathUserNkey(b)...)
	return paths
}

// createSeed creates a new Nkey seed
func createSeed(prefix nkeys.PrefixByte) (string, error) {

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

func validateSeed(seed string, expected nkeys.PrefixByte) error {
	// decode seed
	decodedSeed, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return err
	}

	prefix, _, err := nkeys.DecodeSeed(decodedSeed)
	if err != nil {
		return err
	}

	if prefix != expected {
		return fmt.Errorf("wrong seed type")
	}

	return nil
}

func convertToKeyPair(seed string) (nkeys.KeyPair, error) {
	// decode seed
	decodedSeed, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, err
	}

	// create keypair
	keypair, err := nkeys.FromSeed(decodedSeed)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}

func readNkey(ctx context.Context, storage logical.Storage, path string) (*NKeyStorage, error) {
	return getFromStorage[NKeyStorage](ctx, storage, path)
}

func deleteNkey(ctx context.Context, storage logical.Storage, path string) error {
	return deleteFromStorage(ctx, storage, path)
}

func toNkeyData(nkey *NKeyStorage) (*NkeyData, error) {
	// convert seed into public/private key data structure
	keypair, err := convertToKeyPair(nkey.Seed)
	if err != nil {
		return nil, err
	}

	pub, err := keypair.PublicKey()
	if err != nil {
		return nil, err
	}

	private, err := keypair.PrivateKey()
	if err != nil {
		return nil, err
	}

	// create response
	d := &NkeyData{
		NKeyStorage: *nkey,
		PublicKey:   pub,
		PrivateKey:  base64.StdEncoding.EncodeToString(private),
	}
	return d, nil
}

func createResponseNkeyData(nkey *NKeyStorage) (*logical.Response, error) {

	d, err := toNkeyData(nkey)
	if err != nil {
		return nil, err
	}

	rval := map[string]interface{}{}
	err = mapstructure.Decode(d, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func addNkey(ctx context.Context, create bool, storage logical.Storage, path string, prefix nkeys.PrefixByte, params NkeyParameters) error {
	seed := params.Seed
	nkey, err := getFromStorage[NKeyStorage](ctx, storage, path)
	if err != nil {
		return err
	}

	if nkey == nil {
		if !create {
			return fmt.Errorf("nkey does not exist")
		}
		nkey = &NKeyStorage{}
	}
	nkey.Seed = seed

	// when no seed is given, generate a new one
	if nkey.Seed == "" {
		nkey.Seed, err = createSeed(prefix)
		if err != nil {
			return err
		}
	} else {
		// when a seed is given, validate it
		err = validateSeed(nkey.Seed, nkeys.PrefixByteOperator)
		if err != nil {
			return err
		}
	}

	// store the nkey
	err = storeInStorage(ctx, storage, path, nkey)
	if err != nil {
		return err
	}

	return nil
}

func listNkeys(ctx context.Context, storage logical.Storage, path string) ([]string, error) {
	return storage.List(ctx, path)
}
