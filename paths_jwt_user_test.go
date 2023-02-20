package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
)

func createUserJWT() string {
	accountKey, _ := nkeys.CreateAccount()
	userKey, _ := nkeys.CreateUser()
	pub, _ := userKey.PublicKey()
	claim := jwt.NewUserClaims(pub)
	encoded, _ := claim.Encode(accountKey)
	return encoded
}

func TestCRUDUserJWTs(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test CRUD for user jwts", func(t *testing.T) {

		path := "jwt/operator/op1/account/acc1/user/u1"

		// first call read/delete/list without creating the key
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
			Path:      "jwt/operator/op1/account/acc1/user",
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
			Data: map[string]interface{}{
				"jwt": createUserJWT(),
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
		assert.True(t, resp.Data["jwt"].(string) != "")

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/acc1/user/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{"keys": []string{"u1"}}, resp.Data)

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
			Data: map[string]interface{}{
				"jwt": createUserJWT(),
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

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})

	t.Run("Test CRUD for multiple user jwts", func(t *testing.T) {
		// create 3 keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("jwt/operator/op1/account/acc1/user/u%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   reqStorage,
				Data: map[string]interface{}{
					"jwt": createUserJWT(),
				},
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/acc1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"u0", "u1", "u2"},
		}, resp.Data)

		// delete the keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("jwt/operator/op1/account/acc1/user/u%d", i)
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
			Path:      "jwt/operator/op1/account/acc1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)

	})

	t.Run("Test user jwt wrong type", func(t *testing.T) {

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "jwt/operator/op1/account/acc1/user/u1",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"jwt": createOperatorJWT(),
			},
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "jwt/operator/op1/account/acc1/user/u1",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"jwt": "wrong jwt",
			},
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

	})

}
