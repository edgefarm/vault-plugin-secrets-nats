package natsbackend

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	v1alpha1 "github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/operator/v1alpha1"
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestCRUDOperatorIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of operator issuer", func(t *testing.T) {

		path := "issue/operator/op1"

		// call read/delete/list without creating the issue
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
			Path:      "issue/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		assert.True(t, reflect.DeepEqual(resp.Data, map[string]interface{}{}))
	})

	t.Run("Test CRUD logic for operator issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1"
		var request map[string]interface{}
		var expected IssueOperatorData
		var current IssueOperatorData

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueOperatorParameters{}, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueOperatorData{
			Operator: "op1",
			Claims:   v1alpha1.OperatorClaims{},
			Status: IssueOperatorStatus{
				Operator: IssueStatus{
					Nkey: true,
					JWT:  true,
				},
				SystemAccount: IssueStatus{
					Nkey: false,
					JWT:  false,
				},
				SystemAccountUser: IssueStatus{
					Nkey: false,
					JWT:  false,
				},
			},
		}

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
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
		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueOperatorParameters{
			Claims: v1alpha1.OperatorClaims{
				Operator: v1alpha1.Operator{
					AccountServerURL: "http://localhost:9090",
				},
			},
		}, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueOperatorData{
			Operator: "op1",
			Claims: v1alpha1.OperatorClaims{
				Operator: v1alpha1.Operator{
					AccountServerURL: "http://localhost:9090",
				},
			},
			Status: IssueOperatorStatus{
				Operator: IssueStatus{
					Nkey: true,
					JWT:  true,
				},
				SystemAccount: IssueStatus{
					Nkey: false,
					JWT:  false,
				},
				SystemAccountUser: IssueStatus{
					Nkey: false,
					JWT:  false,
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
		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]interface{}{"keys": []string{"op1"}}, resp.Data)

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

	t.Run("Test CRUD for multiple operator jwts", func(t *testing.T) {
		// create 3 keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("issue/operator/op%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op0", "op1", "op2"},
		}, resp.Data)

		// delete the keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("issue/operator/op%d", i)
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
			Path:      "issue/operator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)

	})

	t.Run("Test CRUD for operator issuer and validate nkeys and jwt's", func(t *testing.T) {
		path := "issue/operator/op1"

		// create the issue only with defaults and read it
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"claims": map[string]interface{}{
					"operator": map[string]interface{}{
						"signingKeys": []interface{}{
							"key1",
							"key2",
							"key3",
						},
					},
				},
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read the nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["seed"].(string) != "")
		assert.True(t, resp.Data["publicKey"].(string) != "")
		assert.True(t, resp.Data["privateKey"].(string) != "")
		seed := resp.Data["seed"].(string)
		seedBytes := []byte(seed)
		assert.NoError(t, err)
		assert.NoError(t, validateSeed(seedBytes, "operator"))

		// read a signing key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/signing/key2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["seed"].(string) != "")
		seed = resp.Data["seed"].(string)
		seedBytes = []byte(seed)
		assert.NoError(t, err)
		assert.NoError(t, validateSeed(seedBytes, "operator"))

		// read the jwt
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["jwt"].(string) != "")
		assert.NoError(t, validateJWT[jwt.OperatorClaims](resp.Data["jwt"].(string)))

		// then delete the key and read keys again
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read the nkey
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		// read the jwt
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		// read a signing key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/signing/key2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

	})

	t.Run("Test update of signing keys", func(t *testing.T) {
		path := "issue/operator/op"

		// create the issue only with defaults and read it
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// list the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/op/signing",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, nil, resp.Data["keys"])

		// update the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "issue/operator/op",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"claims": map[string]interface{}{
					"operator": map[string]interface{}{
						"signingKeys": []interface{}{
							"key1",
							"key2",
							"key3",
						},
					},
				},
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read a signing key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op/signing/key2",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["seed"].(string) != "")
		seed := resp.Data["seed"].(string)
		seedBytes := []byte(seed)
		assert.NoError(t, err)
		assert.NoError(t, validateSeed(seedBytes, "operator"))

		// list the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/op/signing",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, []string{"key1", "key2", "key3"}, resp.Data["keys"])

		// update the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "issue/operator/op",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"claims": map[string]interface{}{
					"operator": map[string]interface{}{
						"signingKeys": []interface{}{
							"key2",
							"key3",
							"key4",
						},
					},
				},
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// list the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/op/signing",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, []string{"key2", "key3", "key4"}, resp.Data["keys"])

	})

	t.Run("Test system account handling", func(t *testing.T) {
		path := "issue/operator/opsys"

		// create without system account
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// list the signing keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/opsys/account",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, nil, resp.Data["keys"])

		// update with system account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"CreateSystemAccount": true,
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// list the account nkeys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/opsys/account",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, []string{DefaultSysAccountName}, resp.Data["keys"])

		// delete the issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})
}
