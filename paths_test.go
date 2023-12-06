package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
)

func cOperatorJWT(operatorSeed string) string {
	operatorKey, _ := nkeys.FromSeed([]byte(operatorSeed))
	pub, _ := operatorKey.PublicKey()
	claim := jwt.NewOperatorClaims(pub)
	encoded, _ := claim.Encode(operatorKey)
	return encoded
}

// we need to test importing nkeys and jwts to issue new accounts and users
func TestXxx(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("import operator nkey", func(t *testing.T) {

		// create operator seed
		seed := genOperatorSeed()

		// import operator nkey
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/op123",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"seed": seed,
			},
		})

		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read operator nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op123",
			Storage:   reqStorage,
		})
		// check operator nkey is the same as imported
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// import operator jwt
		operatorJWT := cOperatorJWT(seed)
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "jwt/operator/op123",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"jwt": operatorJWT,
			},
		})

		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// issue account from operator
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op123/account/acc123",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// get issued account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "issue/operator/op123/account/acc123",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// get issued account jwt
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op123/account/acc123",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// unmarshal jwt
		j, _ := jwt.Decode(resp.Data["jwt"].(string))
		iss := j.Claims().Issuer

		// get pubkey from operator seed
		operatorKey, _ := nkeys.FromSeed([]byte(seed))
		pub, _ := operatorKey.PublicKey()

		// check account is issued by operator pubkey
		assert.Equal(t, pub, iss)
	})
}
