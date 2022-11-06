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
		_, err := testCreate(t, b, reqStorage, "cmd/operator", map[string]interface{}{
			"NKeyID":                "operator1",
			"SigningKeys":           []string{},
			"StrictSigningKeyUsage": false,
			"AccountServerURL":      "http://localhost:9090",
			"SystemAccount":         "sys",
		})
		assert.NoError(t, err)

		// read	operator nkey
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
	})
}

func testCreate(t *testing.T, b *NatsBackend, s logical.Storage, path string, d map[string]interface{}) (*logical.Response, error) {
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
