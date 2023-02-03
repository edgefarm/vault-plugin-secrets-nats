package natsbackend

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
	"gonum.org/v1/gonum/stat/combin"
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

	t.Run("Test CRUD logic for user issuer", func(t *testing.T) {

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
			Status: IssueUserStatus{
				User: IssueStatus{
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
			Status: IssueUserStatus{
				User: IssueStatus{
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

	t.Run("Test issued nkeys, jwts and creds", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/user/us1"
		var request map[string]interface{}

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

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the creds
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////
		// Then delete the issue
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////////
		// ... and try to read again
		/////////////////////////////

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		//////////////////////////
		// read the jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		//////////////////////////
		// read the creds
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("Test sys account with default-push user", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = fmt.Sprintf("operator/op1/account/%s/user/%s", DefaultSysAccountName, DefaultPushUser)
		var issueUserPath = "issue/" + path
		var nkeyUserPath = "nkey/" + path
		var jwtUserPath = "jwt/" + path
		var credsUserPath = "creds/" + path
		var request map[string]interface{}

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
			Path:      "issue/operator/op1/account/" + DefaultSysAccountName,
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		mapstructure.Decode(IssueUserParameters{}, &request)

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      issueUserPath,
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
			Path:      issueUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      nkeyUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      jwtUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the creds
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////
		// Then delete the issue
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      issueUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////////
		// ... and try to read again
		/////////////////////////////

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      nkeyUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		//////////////////////////
		// read the jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      jwtUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		//////////////////////////
		// read the creds
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})

}

// TestWithUserRandomizedOrder tests that the backend can handle
// requests in a random order. In the end everything should be fine.
// This test tests all permutations of the following actions:
// - create operator
// - create sys account
// - create default sys account user
// - create account
// - create user
// After each permutation there will be a check that asserts that
// - the JWT of the operator has reference of the sys account public key
// - the JWT of the default sys account user has reference of the sys account public key
// - the JWT of the account has reference of the operator public key
// - the JWT of the user has reference of its accounts public key
func TestWithUserRandomizedOrder(t *testing.T) {
	type action struct {
		description string
		req         *logical.Request
	}

	operatorName := "op1"
	accountName := "acc1"
	userName := "user1"

	b, reqStorage := getTestBackend(t)
	actions := []action{
		{
			description: "create operator without sys account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			},
		},
		{
			description: "create sys account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + DefaultSysAccountName,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			},
		},
		{
			description: "create sys account user push-default",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + DefaultSysAccountName + "/user/" + DefaultPushUser,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			},
		},
		{
			description: "create account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + accountName,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			},
		},
		{
			description: "create user for account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + accountName + "/user/" + userName,
				Storage:   reqStorage,
				Data:      map[string]interface{}{},
			},
		},
	}

	check := func(identifier string) {
		// Check operator issue, nkey and jwt
		err := listPath(b, reqStorage, "issue/operator/", map[string]interface{}{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/", map[string]interface{}{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/", map[string]interface{}{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		// Check account issue, nkey and jwt
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/", map[string]interface{}{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/"+operatorName+"/account/", map[string]interface{}{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/", map[string]interface{}{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		// Check default push-user issue (from sys account), nkey and jwt
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/"+DefaultSysAccountName+"/user/", map[string]interface{}{"keys": []string{DefaultPushUser}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/"+operatorName+"/account/"+DefaultSysAccountName+"/user/", map[string]interface{}{"keys": []string{DefaultPushUser}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/"+DefaultSysAccountName+"/user/", map[string]interface{}{"keys": []string{DefaultPushUser}})
		bailOutOnErr(t, identifier, err)
		// Check user issue, nkey and jwt
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/"+accountName+"/user/", map[string]interface{}{"keys": []string{userName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/"+operatorName+"/account/"+accountName+"/user/", map[string]interface{}{"keys": []string{userName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/"+accountName+"/user/", map[string]interface{}{"keys": []string{userName}})
		bailOutOnErr(t, identifier, err)

		// Check JWTs for validity
		err = checkOperatorJWTForSysAccount(b, reqStorage, operatorName)
		bailOutOnErr(t, identifier, err)
		err = checkAccountJWTForOperator(b, reqStorage, operatorName, DefaultSysAccountName)
		bailOutOnErr(t, identifier, err)
		err = checkAccountJWTForOperator(b, reqStorage, operatorName, accountName)
		bailOutOnErr(t, identifier, err)
		err = checkUserJWTForAccount(b, reqStorage, operatorName, DefaultSysAccountName, DefaultPushUser)
		bailOutOnErr(t, identifier, err)
		err = checkUserJWTForAccount(b, reqStorage, operatorName, accountName, userName)
		bailOutOnErr(t, identifier, err)
	}

	permuations := combin.Permutations(len(actions), len(actions))
	for _, permutation := range permuations {
		identifier := fmt.Sprintf("Test permuation: %+v", permutation)
		t.Run(identifier, func(t *testing.T) {
			t.Logf("Test permuation: %+v", permutation)
			for _, actionIndex := range permutation {
				action := actions[actionIndex]
				resp, err := b.HandleRequest(context.Background(), action.req)
				if resp.IsError() {
					t.Fatal(errors.New(resp.Data["error"].(string)))
				}
				assert.False(t, resp.IsError())
				bailOutOnErr(t, identifier, err)
			}
			check(identifier)
		})
	}
}

func bailOutOnErr(t *testing.T, identifier string, err error) {
	if err != nil {
		t.Errorf("%s: %+v\n", identifier, err)
	}
}

func listPath(b *NatsBackend, reqStorage logical.Storage, path string, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      path,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error listing nkeys: %s", resp.Error().Error())
	}

	if !reflect.DeepEqual(resp.Data, expected) {
		return fmt.Errorf("path: %s, op: list, expected: %+v, got: %+v", path, expected, resp.Data)
	}
	return nil
}

func checkOperatorJWTForSysAccount(b *NatsBackend, reqStorage logical.Storage, operatorName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading operator JWT: %s", resp.Error().Error())
	}
	var current JWTData
	mapstructure.Decode(resp.Data, &current)
	operatorClaims, err := jwt.DecodeOperatorClaims(current.JWT)
	if err != nil {
		return err
	}
	// get sys account public key
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + DefaultSysAccountName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading sys account JWT: %s", resp.Error().Error())
	}
	var sysAccount JWTData
	mapstructure.Decode(resp.Data, &sysAccount)
	sysAccountClaims, err := jwt.DecodeAccountClaims(sysAccount.JWT)
	if err != nil {
		return err
	}
	if operatorClaims.SystemAccount != sysAccountClaims.Subject {
		return fmt.Errorf("operator JWT does not reference sys account")
	}
	return nil
}

func checkAccountJWTForOperator(b *NatsBackend, reqStorage logical.Storage, operatorName string, accountName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading operator JWT: %s", resp.Error().Error())
	}
	var operator JWTData
	mapstructure.Decode(resp.Data, &operator)
	operatorClaims, err := jwt.DecodeOperatorClaims(operator.JWT)
	if err != nil {
		return err
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + accountName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading account JWT: %s", resp.Error().Error())
	}
	var account JWTData
	mapstructure.Decode(resp.Data, &account)
	accountClaims, err := jwt.DecodeAccountClaims(account.JWT)
	if err != nil {
		return err
	}
	if accountClaims.Issuer != operatorClaims.Subject {
		return fmt.Errorf("account JWT does not reference operator")
	}
	return nil
}

func checkUserJWTForAccount(b *NatsBackend, reqStorage logical.Storage, operatorName string, accountName string, userName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + accountName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading account JWT: %s", resp.Error().Error())
	}
	var account JWTData
	mapstructure.Decode(resp.Data, &account)
	accountClaims, err := jwt.DecodeAccountClaims(account.JWT)
	if err != nil {
		return err
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + accountName + "/user/" + userName,
		Storage:   reqStorage,
		Data:      map[string]interface{}{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading user JWT: %s", resp.Error().Error())
	}
	var user JWTData
	mapstructure.Decode(resp.Data, &user)
	userClaims, err := jwt.DecodeUserClaims(user.JWT)
	if err != nil {
		return err
	}
	if userClaims.Issuer != accountClaims.Subject {
		return fmt.Errorf("user JWT does not reference account")
	}
	return nil
}
