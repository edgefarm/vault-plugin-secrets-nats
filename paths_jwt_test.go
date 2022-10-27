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

	t.Run("Test operator jwt", func(t *testing.T) {
		keypair, _ := nkeys.CreateOperator()
		pkey, _ := keypair.PublicKey()
		opClaim := jwt.NewOperatorClaims(pkey)
		encoded, err := opClaim.Encode(keypair)
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

		t.Log("resp.Data", resp.Data)

		assert.Equal(t, len(resp.Data), 1)
		assert.Equal(t, encoded, resp.Data["jwt"])
	})

	// t.Run("Test account jwt", func(t *testing.T) {

	// 	_, err := testJWTCreate(t, b, reqStorage, "jwt/account/ac1", map[string]interface{}{
	// 		"name": "ac1",
	// 	})

	// 	assert.NoError(t, err)

	// 	resp, err := b.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.ReadOperation,
	// 		Path:      "jwt/account/ac1",
	// 		Storage:   reqStorage,
	// 	})

	// 	assert.NoError(t, err)
	// 	assert.Equal(t, len(resp.Data), 2)
	// })

	// t.Run("Test user jwt", func(t *testing.T) {

	// 	// Create new jwt
	// 	_, err := testJWTCreate(t, b, reqStorage, "jwt/user/us1", map[string]interface{}{
	// 		"name": "us1",
	// 	})

	// 	assert.NoError(t, err)

	// 	// Readout jwt
	// 	resp, err := b.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.ReadOperation,
	// 		Path:      "jwt/user/us1",
	// 		Storage:   reqStorage,
	// 	})

	// 	assert.NoError(t, err)
	// 	assert.Equal(t, len(resp.Data), 2)

	// 	// Generate second jwt, but provide existing jwt per params
	// 	var ctx context.Context
	// 	keypair, err := generateJWT(ctx, jwts.PrefixByteUser)
	// 	assert.NoError(t, err)

	// 	_, err = testJWTCreate(t, b, reqStorage, "jwt/user/us2", map[string]interface{}{
	// 		"public_key":  keypair.PublicKey,
	// 		"private_key": keypair.PrivateKey,
	// 	})
	// 	assert.NoError(t, err)

	// 	// Readout second jwt
	// 	resp, err = b.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.ReadOperation,
	// 		Path:      "jwt/user/us2",
	// 		Storage:   reqStorage,
	// 	})

	// 	// TODO: check jwt
	// 	assert.NoError(t, err)
	// 	assert.Equal(t, len(resp.Data), 2)

	// 	assert.Equal(t, keypair.PublicKey, resp.Data["KeyPair"].(map[string]interface{})["PublicKey"])
	// 	assert.Equal(t, keypair.PrivateKey, resp.Data["KeyPair"].(map[string]interface{})["PrivateKey"])

	// 	// TODO: generate jwt only with public key

	// 	// TODO: try and fail to create jwt only with private key
	// })
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
