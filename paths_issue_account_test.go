package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	accountv1 "github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/account/v1alpha1"
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestCRUDAccountIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of account issuer", func(t *testing.T) {

		path := "issue/operator/op1/account/ac1"

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
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
			Path:      "issue/operator/op1/account/",
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
		var path string = "issue/operator/op1/account/ac1"
		var request map[string]interface{}
		var expected IssueAccountData
		var current IssueAccountData

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueAccountParameters{}, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueAccountData{
			Operator:      "op1",
			Account:       "ac1",
			UseSigningKey: "",
			Claims:        accountv1.AccountClaims{},
			Status: IssueAccountStatus{
				Account: IssueStatus{
					Nkey: true,
					JWT:  true,
				},
			},
		}

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
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
		issue := IssueAccountParameters{
			Claims: accountv1.AccountClaims{
				Account: accountv1.Account{
					Limits: accountv1.OperatorLimits{
						AccountLimits: accountv1.AccountLimits{
							Imports: 10,
						},
					},
				},
			},
		}
		tmp, err := json.Marshal(issue)
		assert.Nil(t, err)
		json.Unmarshal(tmp, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = IssueAccountData{
			Operator: "op1",
			Account:  "ac1",
			Claims: accountv1.AccountClaims{
				Account: accountv1.Account{
					Limits: accountv1.OperatorLimits{
						AccountLimits: accountv1.AccountLimits{
							Imports: 10,
						},
					},
				},
			},
			Status: IssueAccountStatus{
				Account: IssueStatus{
					Nkey: true,
					JWT:  true,
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
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]interface{}{"keys": []string{"ac1"}}, resp.Data)

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

	t.Run("Test CRUD for multiple account jwts", func(t *testing.T) {

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// create 3 keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("issue/operator/op1/account/ac%d", i)
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
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac0", "ac1", "ac2"},
		}, resp.Data)

		// delete the keys
		for i := 0; i < 3; i++ {
			path := fmt.Sprintf("issue/operator/op1/account/ac%d", i)
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
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)
	})

}

func TestAccountBeforeOperatorCreatingSysAccount(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	// Test name: Account before Operator creating SYS account
	// Test overwiew: This test creates an account issue before the operator is created. Once the operator is created,
	// it also creates the SYS account.
	// Test steps:
	// 1. The account for ac1 issue should create a nkey but no JWT because of the missing system account.
	// 2. During creating of the operator issue, the operators nkey and JWT is created. The operator also creates
	// the sys account and puts the sys account's information in it's JWT.
	// 3. After creating the operator all accounts JWTs are created referencing the operators public key as issuer in the JWT claims.
	t.Run("Account before Operator creating SYS account", func(t *testing.T) {
		path := "issue/operator/op1/account"
		request := map[string]interface{}{}
		var current JWTData
		var acountJWT JWTData

		// 1. The accounts for ac1 and ac2 issue should create a nkey but no JWT because of the missing system account.
		// 1.1a create the account
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path + "/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		// 1.1b create the account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path + "/ac2",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// 1.2 list the accounts - ac1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1", "ac2"},
		}, resp.Data)

		// 1.3 list the JWTs for accounts - none present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)

		// 2. During creating of the operator issue, the operators nkey and JWT is created. The operator also creates
		// the sys account and puts the sys account's information in it's JWT.
		// 2.1 create operator and let it create the sys account
		stm.StructToMap(&IssueOperatorParameters{
			CreateSystemAccount: true,
		}, &request)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      request,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// 2.2 list the operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.3 list the JWTs for operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.4 list the nkeys for operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.5 check the operator JWT - sys account information present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		stm.MapToStruct(resp.Data, &current)
		op1Claims, err := jwt.DecodeOperatorClaims(current.JWT)
		assert.NoError(t, err)
		// get sys account public key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/" + DefaultSysAccountName,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		var sysAccount JWTData
		stm.MapToStruct(resp.Data, &sysAccount)
		sysAccountClaims, err := jwt.DecodeAccountClaims(sysAccount.JWT)
		assert.NoError(t, err)
		assert.Equal(t, op1Claims.SystemAccount, sysAccountClaims.Subject)

		// 3. After creating the operator all accounts JWTs are created referencing the operators public key as issuer in the JWT claims.
		// 3.1 list the accounts - ac1, ac2 and SYS should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1", "ac2", DefaultSysAccountName},
		}, resp.Data)

		// 3.2 list the JWTs for accounts - ac1 and SYS should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1", "ac2", DefaultSysAccountName},
		}, resp.Data)

		// 3.3a check account acc1 JWT that issuer is operator public key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		stm.MapToStruct(resp.Data, &acountJWT)
		ac1Claims, err := jwt.DecodeAccountClaims(acountJWT.JWT)
		assert.NoError(t, err)
		assert.Equal(t, ac1Claims.Issuer, op1Claims.Subject)

		// 3.3b check accounts acc2 JWT that issuer is operator public key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		stm.MapToStruct(resp.Data, &acountJWT)
		ac2Claims, err := jwt.DecodeAccountClaims(acountJWT.JWT)
		assert.NoError(t, err)
		assert.Equal(t, ac2Claims.Issuer, op1Claims.Subject)

	})
}
func TestAccountBeforeOperatorAndSysAccount(t *testing.T) {

	b, reqStorage := getTestBackend(t)
	// Test name: Account before Operator and SYS account
	// Test overwiew: This test creates an account issue before the operator and a system account is created.
	// Test steps:
	// 1. The account for ac1 issue should create a nkey but no JWT because of the missing system account.
	// 2. During creating of the operator issue, the operators nkey and JWT is created. However the operators JWT
	// is missing information about the system account.
	// 3. After creating the system account, the operators JWT is updated with the system account information and
	// all accounts JWTs are created referencing the operators public key as issuer in the JWT claims.
	t.Run("Account before Operator and SYS account", func(t *testing.T) {
		path := "issue/operator/op1/account/ac1"
		var current JWTData

		// 1. The account for ac1 issue should create a nkey but no JWT because of the missing system account.
		// 1.1 create the account
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// 1.2 list the accounts - ac1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1"},
		}, resp.Data)

		// 1.3 list the JWTs for accounts - none present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)

		// 2. During creating of the operator issue, the operators nkey and JWT is created. However the operators JWT
		// is missing information about the system account.
		// 2.1 create operator with no sys account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// 2.2 list the operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.3 list the JWTs for operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.4 list the nkeys for operators - op1 should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "nkey/operator/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"op1"},
		}, resp.Data)

		// 2.5 check the operator JWT - no sys account information present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		stm.MapToStruct(resp.Data, &current)
		op1Claims, err := jwt.DecodeOperatorClaims(current.JWT)
		assert.NoError(t, err)
		assert.Equal(t, op1Claims.SystemAccount, "")

		// 3. After creating the system account, the operators JWT is updated with the system account information and
		// all accounts JWTs are created referencing the operators public key as issuer in the JWT claims.
		// 3.1 create sys account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/" + DefaultSysAccountName,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// 3.2 list the accounts - ac1 and SYS should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1", DefaultSysAccountName},
		}, resp.Data)

		// 3.3 list the JWTs for accounts - ac1 and SYS should be present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"ac1", DefaultSysAccountName},
		}, resp.Data)

		// 3.4 check the operator JWT - sys account information present
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		stm.MapToStruct(resp.Data, &current)
		op1Claims, err = jwt.DecodeOperatorClaims(current.JWT)
		assert.NoError(t, err)
		// get sys account public key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/" + DefaultSysAccountName,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		var sysAccount JWTData
		stm.MapToStruct(resp.Data, &sysAccount)
		sysAccountClaims, err := jwt.DecodeAccountClaims(sysAccount.JWT)
		assert.NoError(t, err)
		assert.Equal(t, op1Claims.SystemAccount, sysAccountClaims.Subject)

		// 3.5 check account ac1 JWT that issuer is operator public key
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		var ac1 JWTData
		stm.MapToStruct(resp.Data, &ac1)
		ac1Claims, err := jwt.DecodeAccountClaims(ac1.JWT)
		assert.NoError(t, err)
		assert.Equal(t, ac1Claims.Issuer, op1Claims.Subject)
	})
}

func Test_UnmarshalIssueAccountParameters(t *testing.T) {
	assert := assert.New(t)
	jsonClaims :=
		`{
			"Account": {
			  "Limits": {
				"Subs": -1,
				"Conn": -1,
				"LeafNodeConn": -1,
				"Data": -1,
				"Payload": -1,
				"WildcardExports": true,
				"Imports": -1,
				"Exports": -1
			  },
			  "Exports": [
				{
				  "Name": "account-monitoring-streams",
				  "Subject": "$SYS.ACCOUNT.*.>",
				  "Type": "stream",
				  "AccountTokenPosition": 3,
				  "Info": {
					"Description": "Account specific monitoring stream",
					"InfoURL": "https://docs.nats.io/nats-server/configuration/sys_accounts"
				  }
				},
				{
				  "Name": "account-monitoring-services",
				  "Subject": "$SYS.ACCOUNT.*.*",
				  "Type": "service",
				  "ResponseType": "Stream",
				  "AccountTokenPosition": 4,
				  "Info": {
					"Description": "Account specific monitoring stream",
					"InfoURL": "https://docs.nats.io/nats-server/configuration/sys_accounts"
				  }
				}
			  ]
			}
		  }`
	claims := &accountv1.AccountClaims{}
	err := json.Unmarshal([]byte(jsonClaims), claims)
	assert.Nil(err)
	fmt.Printf("%+v\n", claims)
}
