package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestOperator mocks the read
// of the operator configuration for Nats.
func TestCmd(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test operator create nkey and jwt command", func(t *testing.T) {

		// create a new operator jwt/key
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"signing_keys":             "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)

		// read operator params
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "cmd/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, "operator1", resp.Data["nkey_id"])
		// TODO: flat fields and test results
		// assert.Equal(t, []interface{}{}, resp.Data["singning_keys"])
		// assert.Equal(t, false, resp.Data["strict_signing_key_usage"])
		// assert.Equal(t, "http://localhost:9090", resp.Data["account_server_url"])
		// assert.Equal(t, "sys", resp.Data["system_account"])

		// list nkeys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, []string{"operator1"}, resp.Data["keys"])

		// read	operator nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/operator1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 4, len(resp.Data))

		// read operator jwt
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Data))

		// update operator jwt/key
		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator2",
				"signing_keys":             "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)

		// list nkeys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, []string{"operator2"}, resp.Data["keys"])

		// read	operator nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/operator2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 4, len(resp.Data))

		// read operator jwt
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Data))

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "cmd/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
	})
}
