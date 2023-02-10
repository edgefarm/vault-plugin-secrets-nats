package natsbackend

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/rs/zerolog/log"
)

// JWTStorage represents a JWT stored in the backend
type JWTStorage struct {
	JWT string `json:"jwt"`
}

// JWTParameters represents the parameters for a JWT operation
type JWTParameters struct {
	Operator string `json:"operator,omitempty"`
	Account  string `json:"account,omitempty"`
	User     string `json:"user,omitempty"`
	JWTStorage
}

// JWTData represents the the data returned by a JWT operation
type JWTData struct {
	JWTStorage
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
	err := stm.StructToMap(d, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func addJWT(ctx context.Context, storage logical.Storage, path string, params JWTParameters) error {
	jwt, err := getFromStorage[JWTStorage](ctx, storage, path)
	if err != nil {
		return err
	}

	if jwt == nil {
		log.Info().Msg("JWT does not exist. creating new one")
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
	l, err := storage.List(ctx, path)
	if err != nil {
		return nil, err
	}
	var sorted []string
	re := regexp.MustCompile(`\/`)
	for _, v := range l {
		if !re.Match([]byte(v)) {
			sorted = append(sorted, v)
		}
	}
	return sorted, nil
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
