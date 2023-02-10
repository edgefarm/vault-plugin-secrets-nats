package natsbackend

// func TestNatsWithAccountServer(t *testing.T) {

// 	/////////////////////////////////////////////////////
// 	// Create all necessary secrets to start nats server
// 	/////////////////////////////////////////////////////

// 	//------------------------
// 	// Prepare
// 	//------------------------

// 	var request map[string]interface{}
// 	b, reqStorage := getTestBackend(t)
// 	var currentOperator IssueOperatorData
// 	var expectedOperator IssueOperatorData
// 	var currentAccount IssueAccountData
// 	var expectedAccount IssueAccountData
// 	//------------------------
// 	// That will be requested
// 	//------------------------

// 	onIssue := "issue/operator/operator"

// 	mstm.StructToMap(&IssueOperatorParameters{
// 		CreateSystemAccount: true,
// 		AccountServerURL:    "nats://localhost:4222",
// 		SyncAccountServer:   true,
// 	}, &request)

// 	//------------------------
// 	// That will be expected
// 	//------------------------
// 	expectedOperator = IssueOperatorData{
// 		Operator:            "operator",
// 		SigningKeys:         []string(nil),
// 		CreateSystemAccount: true,
// 		AccountServerURL:    "nats://localhost:4222",
// 		SyncAccountServer:   true,
// 		Claims:              operatorv1.OperatorClaims{},
// 		Status: IssueOperatorStatus{
// 			Operator: IssueStatus{
// 				Nkey: true,
// 				JWT:  true,
// 			},
// 			SystemAccount: IssueStatus{
// 				Nkey: true,
// 				JWT:  true,
// 			},
// 			SystemAccountUser: IssueStatus{
// 				Nkey: true,
// 				JWT:  true,
// 			},
// 		},
// 	}

// 	//------------------------
// 	// create issue
// 	//------------------------
// 	resp, err := b.HandleRequest(context.Background(), &logical.Request{
// 		Operation: logical.CreateOperation,
// 		Path:      onIssue,
// 		Storage:   reqStorage,
// 		Data:      request,
// 	})
// 	assert.NoError(t, err)
// 	assert.False(t, resp.IsError())

// 	//////////////////////////
// 	// read the created issue
// 	//////////////////////////
// 	resp, err = b.HandleRequest(context.Background(), &logical.Request{
// 		Operation: logical.ReadOperation,
// 		Path:      onIssue,
// 		Storage:   reqStorage,
// 	})
// 	assert.NoError(t, err)
// 	assert.False(t, resp.IsError())

// 	//////////////////////////////////
// 	// Compare the expected and current
// 	//////////////////////////////////
// 	stm.MapToStruct(resp.Data, &currentOperator)
// 	assert.Equal(t, expectedOperator, currentOperator)

// 	/////////////////////////////
// 	// read system account issue
// 	// created by the operator
// 	/////////////////////////////
// 	resp, err = b.HandleRequest(context.Background(), &logical.Request{
// 		Operation: logical.ReadOperation,
// 		Path:      onIssue + "/account/" + DefaultSysAccountName,
// 		Storage:   reqStorage,
// 	})
// 	assert.NoError(t, err)
// 	assert.False(t, resp.IsError())

// 	//------------------------
// 	// That will be expected
// 	//------------------------
// 	expectedAccount = IssueAccountData{
// 		Operator:      "operator",
// 		Account:       DefaultSysAccountName,
// 		UseSigningKey: "",
// 		SigningKeys:   []string(nil),
// 		Claims: accountv1.AccountClaims{
// 			Account: accountv1.Account{
// 				Exports: []accountv1.Export{
// 					{
// 						Name:                 "account-monitoring-services",
// 						Subject:              "$SYS.REQ.ACCOUNT.*.*",
// 						Type:                 "Service",
// 						ResponseType:         jwt.ResponseTypeStream,
// 						AccountTokenPosition: 4,
// 						Info: common.Info{
// 							Description: `Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO`,
// 							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
// 						},
// 					},
// 					{
// 						Name:                 "account-monitoring-streams",
// 						Subject:              "$SYS.ACCOUNT.*.>",
// 						Type:                 "Stream",
// 						AccountTokenPosition: 3,
// 						Info: common.Info{
// 							Description: `Account specific monitoring stream`,
// 							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
// 						},
// 					},
// 				},
// 				Limits: accountv1.OperatorLimits{
// 					NatsLimits: common.NatsLimits{
// 						Subs:    -1,
// 						Data:    -1,
// 						Payload: -1,
// 					},
// 					AccountLimits: accountv1.AccountLimits{
// 						Imports:         -1,
// 						Exports:         -1,
// 						WildcardExports: true,
// 						Conn:            -1,
// 						LeafNodeConn:    -1,
// 					},
// 				},
// 			},
// 		},
// 		Status: IssueAccountStatus{
// 			Account: IssueStatus{
// 				Nkey: true,
// 				JWT:  true,
// 			},
// 			AccountServer: AccountServerStatus{
// 				Synced:   false,
// 				LastSync: 0,
// 			},
// 		},
// 	}

// 	stm.MapToStruct(resp.Data, &currentAccount)
// 	assert.Equal(t, expectedAccount, currentAccount)

// }
