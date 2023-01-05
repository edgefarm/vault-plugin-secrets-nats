package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestNatsWithAccountServer(t *testing.T) {

	/////////////////////////////////////////////////////
	// Create all necessary secrets to start nats server
	/////////////////////////////////////////////////////

	//------------------------
	// Prepare
	//------------------------

	var request map[string]interface{}
	b, reqStorage := getTestBackend(t)
	var currentOperator IssueOperatorData
	var expectedOperator IssueOperatorData
	var currentAccount IssueAccountData
	var expectedAccount IssueAccountData
	//------------------------
	// That will be requested
	//------------------------

	onIssue := "issue/operator/operator"

	mapstructure.Decode(IssueOperatorParameters{
		CreateSystemAccount: true,
		AccountServerURL:    "nats://localhost:4222",
		SyncAccountServer:   true,
	}, &request)

	//------------------------
	// That will be expected
	//------------------------
	expectedOperator = IssueOperatorData{
		Operator:            "operator",
		SigningKeys:         []string(nil),
		CreateSystemAccount: true,
		SystemAccount:       "SYS",
		SystemAccountUser:   "SYS",
		AccountServerURL:    "nats://localhost:4222",
		SyncAccountServer:   true,
		Claims:              jwt.OperatorClaims{},
		Status: IssueOperatorStatus{
			Operator: IssueStatus{
				Nkey: true,
				JWT:  true,
			},
			SystemAccount: IssueStatus{
				Nkey: true,
				JWT:  true,
			},
			SystemAccountUser: IssueStatus{
				Nkey: true,
				JWT:  true,
			},
		},
	}

	//------------------------
	// create issue
	//------------------------
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      onIssue,
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
		Path:      onIssue,
		Storage:   reqStorage,
	})
	assert.NoError(t, err)
	assert.False(t, resp.IsError())

	//////////////////////////////////
	// Compare the expected and current
	//////////////////////////////////
	mapstructure.Decode(resp.Data, &currentOperator)
	assert.Equal(t, expectedOperator, currentOperator)

	/////////////////////////////
	// read system account issue
	// created by the operator
	/////////////////////////////
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      onIssue + "/account/SYS",
		Storage:   reqStorage,
	})
	assert.NoError(t, err)
	assert.False(t, resp.IsError())

	//------------------------
	// That will be expected
	//------------------------
	expectedAccount = IssueAccountData{
		Operator:      "operator",
		Account:       "SYS",
		UseSigningKey: "",
		SigningKeys:   []string(nil),
		Claims: jwt.AccountClaims{
			Account: jwt.Account{
				Exports: []*jwt.Export{
					{
						Name:                 "account-monitoring-services",
						Subject:              "$SYS.REQ.ACCOUNT.*.*",
						Type:                 jwt.Service,
						TokenReq:             false,
						Revocations:          nil,
						ResponseType:         "Stream",
						ResponseThreshold:    0,
						Latency:              nil,
						AccountTokenPosition: 4,
						Advertise:            false,
						Info: jwt.Info{
							Description: "Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
					{
						Name:                 "account-monitoring-streams",
						Subject:              "$SYS.ACCOUNT.*.>",
						Type:                 jwt.Stream,
						TokenReq:             false,
						Revocations:          nil,
						ResponseType:         "",
						ResponseThreshold:    0,
						Latency:              nil,
						AccountTokenPosition: 3,
						Advertise:            false,
						Info: jwt.Info{
							Description: "Account specific monitoring stream",
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
				},
			},
		},
		Status: IssueAccountStatus{
			Account: IssueStatus{
				Nkey: true,
				JWT:  true,
			},
			AccountServer: AccountServerStatus{
				Synced:   false,
				LastSync: 0,
			},
		},
	}

	mapstructure.Decode(resp.Data, &currentAccount)
	assert.Equal(t, expectedAccount, currentAccount)

}
