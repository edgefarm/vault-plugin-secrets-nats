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

// JWTStorage represents a JWT stored in the backend
type JWTStorage struct {
	JWT string `mapstructure:"jwt"`
}

// JWTParameters represents the parameters for a JWT operation
type JWTParameters struct {
	Operator   string `mapstructure:"operator,omitempty"`
	Account    string `mapstructure:"account,omitempty"`
	User       string `mapstructure:"user,omitempty"`
	JWTStorage `mapstructure:",squash"`
}

// JWTData represents the the data returned by a JWT operation
type JWTData struct {
	JWTStorage `mapstructure:",squash"`
}

func pathJWT(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorJWT(b)...)
	paths = append(paths, pathUserJWT(b)...)
	paths = append(paths, pathAccountJWT(b)...)
	return paths
}

func readJWT(ctx context.Context, storage logical.Storage, path string) (*JWTStorage, error) {
	return getFromStorage[JWTStorage](ctx, storage, path)
}

func deleteJWT(ctx context.Context, storage logical.Storage, path string) error {
	return deleteFromStorage(ctx, storage, path)
}

func createResponseJWTData(jwt *JWTStorage) (*logical.Response, error) {
	d := &JWTData{
		JWTStorage: *jwt,
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

func addJWT(ctx context.Context, create bool, storage logical.Storage, path string, params JWTParameters) error {
	jwt, err := getFromStorage[JWTStorage](ctx, storage, path)
	if err != nil {
		return err
	}

	if jwt == nil {
		if !create {
			return fmt.Errorf("jwt does not exist")
		}
		jwt = &JWTStorage{}
	}

	jwt.JWT = params.JWT

	// store the nkey
	err = storeInStorage(ctx, storage, path, jwt)
	if err != nil {
		return err
	}

	return nil
}

func listJWTs(ctx context.Context, storage logical.Storage, path string) ([]string, error) {
	return storage.List(ctx, path)
}

func validateJWT[T any, P interface{ *T }](token string) error {
	claims, err := jwt.Decode(token)
	if err != nil {
		return fmt.Errorf("error decoding jwt: %s", err.Error())
	}
	_, ok := claims.(P)
	if !ok {
		return errors.New("jwt token has wrong claim type")
	}

	return nil
}
