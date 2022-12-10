package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestCRUDUserIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of user issuer", func(t *testing.T) {

		path := "issue/operator/op1/account/ac1/user/us1"

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// call read/delete/list without creating the issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
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
			Path:      "issue/operator/op1/account/acc1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]interface{}{})

	})

	t.Run("Test CRUD logic for account issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/user/us1"
		var request map[string]interface{}
		var expected IssueUserData
		var current IssueUserData

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		mapstructure.Decode(IssueUserParameters{}, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueUserData{
			Operator:      "op1",
			Account:       "ac1",
			User:          "us1",
			UseSigningKey: "",
			Claims:        jwt.UserClaims{},
		}

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the created issue
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		mapstructure.Decode(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////
		// That will be requested
		//////////////////////////
		mapstructure.Decode(IssueUserParameters{
			Claims: jwt.UserClaims{
				User: jwt.User{
					UserPermissionLimits: jwt.UserPermissionLimits{
						Limits: jwt.Limits{
							NatsLimits: jwt.NatsLimits{
								Subs: 1,
							},
						},
					},
				},
			},
		}, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueUserData{
			Operator: "op1",
			Account:  "ac1",
			User:     "us1",
			Claims: jwt.UserClaims{
				User: jwt.User{
					UserPermissionLimits: jwt.UserPermissionLimits{
						Limits: jwt.Limits{
							NatsLimits: jwt.NatsLimits{
								Subs: 1,
							},
						},
					},
				},
			},
		}

		//////////////////////////////////
		// Update with the requested data
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Read the updated data back
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		mapstructure.Decode(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/ac1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]interface{}{"keys": []string{"us1"}}, resp.Data)

		/////////////////////////
		// Then delete the key
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and try to read it
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		//////////////////////////
		// Then recreate the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... read the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and delete again
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})
}
