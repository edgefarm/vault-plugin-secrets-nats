package natsbackend

import (
	"context"
	"encoding/base64"
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
		assert.Equal(t, 4, len(resp.Data))
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
		assert.Equal(t, 4, len(resp.Data))
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
		assert.Equal(t, 4, len(resp.Data))

		// Generate second nkey, but provide existing nkey per params
		var ctx context.Context
		keypair, err := createKeyPair(ctx, nkeys.PrefixByteUser)
		assert.NoError(t, err)

		_, err = testNkeyCreate(t, b, reqStorage, "nkey/user/us2", map[string]interface{}{
			"seed": keypair.Seed,
		})
		assert.NoError(t, err)

		// Readout second nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/user/us2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 4, len(resp.Data))
		assert.Equal(t, keypair.Seed, resp.Data["seed"])
		raw, err := base64.StdEncoding.DecodeString(resp.Data["seed"].(string))
		assert.NoError(t, err)
		nk, err := nkeys.FromSeed(raw)
		assert.NoError(t, err)
		pub, err := nk.PublicKey()
		assert.NoError(t, err)
		assert.Equal(t, pub, resp.Data["public_key"])
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
