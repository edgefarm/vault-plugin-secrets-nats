package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

// JWTStorage represents a Creds stored in the backend
type CredsStorage struct {
	Creds string `mapstructure:"creds"`
}

// CredsParameters represents the parameters for a Creds operation
type CredsParameters struct {
	Operator     string `mapstructure:"operator,omitempty"`
	Account      string `mapstructure:"account,omitempty"`
	User         string `mapstructure:"user,omitempty"`
	CredsStorage `mapstructure:",squash"`
}

// CredsData represents the the data returned by a Creds operation
type CredsData struct {
	CredsStorage `mapstructure:",squash"`
}

func pathCreds(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathUserCreds(b)...)
	return paths
}

func readCreds(ctx context.Context, storage logical.Storage, path string) (*CredsStorage, error) {
	return getFromStorage[CredsStorage](ctx, storage, path)
}

func deleteCreds(ctx context.Context, storage logical.Storage, path string) error {
	return deleteFromStorage(ctx, storage, path)
}

func createResponseCredsData(creds *CredsStorage) (*logical.Response, error) {
	d := &CredsData{
		CredsStorage: *creds,
	}

	rval := map[string]interface{}{}
	err := mapstructure.Decode(d, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func addCreds(ctx context.Context, create bool, storage logical.Storage, path string, params CredsParameters) error {
	creds, err := getFromStorage[CredsStorage](ctx, storage, path)
	if err != nil {
		return err
	}

	if creds == nil {
		if !create {
			return fmt.Errorf("creds does not exist")
		}
		creds = &CredsStorage{}
	}

	creds.Creds = params.Creds

	// store the nkey
	err = storeInStorage(ctx, storage, path, creds)
	if err != nil {
		return err
	}

	return nil
}

func listCreds(ctx context.Context, storage logical.Storage, path string) ([]string, error) {
	return storage.List(ctx, path)
}
