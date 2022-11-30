package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestCmdCreateUser(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("No account_signing_key, no nkey_id", func(t *testing.T) {
		var err error
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// create account, test setting all fields
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myAccount",
			Data: map[string]interface{}{
				"nkey_id": "myAccount",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// read account params
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/myAccount",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		// accountPubKey := resp.Data["public_key"].(string)

		// create user, test setting all fields
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myAccount/user/myUser",
			Data:      map[string]interface{}{
				// "nkey_id": "myUser",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// resp, err = b.HandleRequest(context.Background(), &logical.Request{
		// 	Operation: logical.ListOperation,
		// 	Path:      "cmd/operator/account/myAccount",
		// 	Data:      map[string]interface{}{
		// 		// "nkey_id": "myUser",
		// 	},
		// 	Storage: reqStorage,
		// })
		// assert.NoError(t, err)
		// assert.NoError(t, resp.Error())
		// fmt.Printf("resp: %+v\n", resp)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "cmd/operator/account/myAccount/user/myUser",
			Data:      map[string]interface{}{
				// "nkey_id": "myUser",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		fmt.Printf("resp: %+v\n", resp)
		assert.NotNil(t, resp)
		// claims, err := claim.Decode(resp.Data[""].(string))
		// assert.NoError(t, err)
		// userClaims := claims.(*claim.UserClaims)
		// assert.Equal(t, userClaims.
	})
}
