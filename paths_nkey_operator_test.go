package natsbackend

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
)

func genOperatorSeed() string {
	key, _ := nkeys.CreateOperator()
	seed, _ := key.Seed()
	return base64.StdEncoding.EncodeToString([]byte(seed))
}

// func genAccountSeed() string {
// 	key, _ := nkeys.CreateAccount()
// 	seed, _ := key.Seed()
// 	return base64.StdEncoding.EncodeToString([]byte(seed))
// }

// func genUserSeed() string {
// 	key, _ := nkeys.CreateUser()
// 	seed, _ := key.Seed()
// 	return base64.StdEncoding.EncodeToString([]byte(seed))
// }

func TestCRUDOperatorNKeys(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test CRUD for operator nkeys", func(t *testing.T) {

		path := "nkey/operator/Op1"

		// first call read/delete/list withour creating the key
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]interface{}{})

		// then create the key and read it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["seed"].(string) != "")
		assert.True(t, resp.Data["public_key"].(string) != "")
		assert.True(t, resp.Data["private_key"].(string) != "")

		seed := resp.Data["seed"].(string)
		seedBytes, err := base64.StdEncoding.DecodeString(seed)
		assert.NoError(t, err)
		assert.NoError(t, validateSeed(seedBytes, nkeys.PrefixByteOperator))

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{"keys": []string{"Op1"}}, resp.Data)

		// then update the key and read it
		seed = genOperatorSeed()
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"seed": seed,
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["seed"].(string) == seed)
		assert.True(t, resp.Data["public_key"].(string) != "")
		assert.True(t, resp.Data["private_key"].(string) != "")
		seed = resp.Data["seed"].(string)
		seedBytes, err = base64.StdEncoding.DecodeString(seed)
		assert.NoError(t, err)
		assert.NoError(t, validateSeed(seedBytes, nkeys.PrefixByteOperator))

		// then delete the key and read it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		// then recreate the key and read and delete it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})

	t.Run("Test CRUD for multiple operator nkeys", func(t *testing.T) {
		// create 3 keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("nkey/operator/op%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   reqStorage,
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op0", "op1", "op2"},
		}, resp.Data)

		// delete the keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("nkey/operator/op%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      path,
				Storage:   reqStorage,
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)

	})
}
