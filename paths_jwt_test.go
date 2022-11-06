package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
)

// TestOperator mocks the read
// of the operator configuration for Nats.
func TestJWT(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	opNkey, _ := nkeys.CreateOperator()
	t.Run("Test operator jwt", func(t *testing.T) {
		pkey, _ := opNkey.PublicKey()
		claim := jwt.NewOperatorClaims(pkey)
		encoded, err := claim.Encode(opNkey)
		assert.NoError(t, err)
		_, err = testJWTCreate(t, b, reqStorage, "jwt/operator", map[string]interface{}{
			"jwt": encoded,
		})
		assert.NoError(t, err)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 1)
		assert.Equal(t, encoded, resp.Data["jwt"])
	})

	accNkey, _ := nkeys.CreateAccount()
	t.Run("Test account jwt", func(t *testing.T) {
		pkey, _ := accNkey.PublicKey()
		claim := jwt.NewAccountClaims(pkey)
		encoded, err := claim.Encode(opNkey)
		assert.NoError(t, err)

		_, err = testJWTCreate(t, b, reqStorage, "jwt/operator/account/ac1", map[string]interface{}{
			"jwt": encoded,
		})

		assert.NoError(t, err)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/ac1",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 1)
		assert.Equal(t, encoded, resp.Data["jwt"])
	})

	usNkey, _ := nkeys.CreateUser()
	t.Run("Test user jwt", func(t *testing.T) {
		pkey, _ := usNkey.PublicKey()
		claim := jwt.NewUserClaims(pkey)
		encoded, err := claim.Encode(accNkey)
		assert.NoError(t, err)

		_, err = testJWTCreate(t, b, reqStorage, "jwt/operator/account/ac1/user/us1", map[string]interface{}{
			"jwt": encoded,
		})

		assert.NoError(t, err)

		// Readout jwt
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/ac1/user/us1",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 1)
	})
}

func testJWTCreate(t *testing.T, b *NatsBackend, s logical.Storage, path string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}
