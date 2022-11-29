package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestCreateDeleteOperatorNkeys(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test delete operator nkey", func(t *testing.T) {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 2, len(resp.Data["keys"].([]string)))
		assert.Contains(t, resp.Data["keys"].([]string), "sk1")
		assert.Contains(t, resp.Data["keys"].([]string), "sk2")
		fmt.Printf("resp: %+v", resp.Data)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "nkey/operator/sk1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Data["keys"].([]string)))
		assert.Contains(t, resp.Data["keys"].([]string), "sk2")
		fmt.Printf("resp: %+v", resp.Data)

		// Delete not existent key, should return no error but doesn't change anything
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "nkey/operator/sk3",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		fmt.Printf("resp: %+v", resp)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "nkey/operator/sk2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		fmt.Printf("resp: %+v", resp)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.Equal(t, resp.Data, map[string]interface{}{})
	})
}
