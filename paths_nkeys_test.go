package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
)

// TestOperator mocks the read
// of the operator configuration for Nats.
func TestNkeys(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test operator nkey", func(t *testing.T) {

		_, err := testNkeyCreate(t, b, reqStorage, "nkey/operator/op1", map[string]interface{}{})

		assert.NoError(t, err)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 2)
		assert.Equal(t, resp.Data["name"], "op1")
	})

	t.Run("Test account nkey", func(t *testing.T) {

		_, err := testNkeyCreate(t, b, reqStorage, "nkey/account/ac1", map[string]interface{}{
			"name": "ac1",
		})

		assert.NoError(t, err)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/ac1",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 2)
	})

	t.Run("Test user nkey", func(t *testing.T) {

		// Create new nkey
		_, err := testNkeyCreate(t, b, reqStorage, "nkey/user/us1", map[string]interface{}{
			"name": "us1",
		})

		assert.NoError(t, err)

		// Readout nkey
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/user/us1",
			Storage:   reqStorage,
		})

		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 2)

		// Generate second nkey, but provide existing nkey per params
		var ctx context.Context
		keypair, err := generateNkey(ctx, nkeys.PrefixByteUser)
		assert.NoError(t, err)

		_, err = testNkeyCreate(t, b, reqStorage, "nkey/user/us2", map[string]interface{}{
			"public_key":  keypair.PublicKey,
			"private_key": keypair.PrivateKey,
		})
		assert.NoError(t, err)

		// Readout second nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/user/us2",
			Storage:   reqStorage,
		})

		// TODO: check nkey
		assert.NoError(t, err)
		assert.Equal(t, len(resp.Data), 2)

		assert.Equal(t, keypair.PublicKey, resp.Data["KeyPair"].(map[string]interface{})["PublicKey"])
		assert.Equal(t, keypair.PrivateKey, resp.Data["KeyPair"].(map[string]interface{})["PrivateKey"])

		// TODO: generate nkey only with public key

		// TODO: try and fail to create nkey only with private key
	})
}

func testNkeyCreate(t *testing.T, b *NatsBackend, s logical.Storage, path string, d map[string]interface{}) (*logical.Response, error) {
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
