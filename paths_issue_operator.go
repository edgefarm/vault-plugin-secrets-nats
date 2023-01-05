package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

type IssueOperatorStorage struct {
	Operator            string             `mapstructure:"operator"`
	CreateSystemAccount bool               `mapstructure:"create_system_account"`
	SystemAccount       string             `mapstructure:"system_account"`
	SystemAccountUser   string             `mapstructure:"sys_user"`
	SigningKeys         []string           `mapstructure:"signing_keys"`
	SyncAccountServer   bool               `mapstructure:"sync_account_server"`
	AccountServerURL    string             `mapstructure:"account_server_url"`
	Claims              jwt.OperatorClaims `mapstructure:"operator_claims"`
}

type IssueOperatorParameters struct {
	Operator            string             `mapstructure:"operator"`
	CreateSystemAccount bool               `mapstructure:"create_system_account"`
	SystemAccount       string             `mapstructure:"system_account"`
	SystemAccountUser   string             `mapstructure:"system_user"`
	SigningKeys         []string           `mapstructure:"signing_keys"`
	AccountServerURL    string             `mapstructure:"account_server_url"`
	SyncAccountServer   bool               `mapstructure:"sync_account_server"`
	Claims              jwt.OperatorClaims `mapstructure:"operator_claims"`
}

type IssueOperatorData struct {
	Operator            string              `mapstructure:"operator"`
	CreateSystemAccount bool                `mapstructure:"create_system_account"`
	SystemAccount       string              `mapstructure:"system_account"`
	SystemAccountUser   string              `mapstructure:"system_account_user"`
	SigningKeys         []string            `mapstructure:"signing_keys"`
	AccountServerURL    string              `mapstructure:"account_server_url"`
	SyncAccountServer   bool                `mapstructure:"sync_account_server"`
	Claims              jwt.OperatorClaims  `mapstructure:"operator_claims"`
	Status              IssueOperatorStatus `mapstructure:"status"`
}

type IssueOperatorStatus struct {
	Operator          IssueStatus `mapstructure:"operator"`
	SystemAccount     IssueStatus `mapstructure:"system_account"`
	SystemAccountUser IssueStatus `mapstructure:"system_account_user"`
}

type IssueStatus struct {
	Nkey bool `mapstructure:"nkey"`
	JWT  bool `mapstructure:"jwt"`
}

func pathOperatorIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"create_system_account": {
					Type:        framework.TypeBool,
					Description: "Create system account (default: false)",
					Required:    false,
				},
				"system_account": {
					Type:        framework.TypeString,
					Description: "Account id to use as system account (default: SYS)",
					Required:    false,
				},
				"system_account_user": {
					Type:        framework.TypeString,
					Description: "User id to use as system account user (default: SYS). Used to sync account jwt's with account server.",
					Required:    false,
				},
				"singning_keys": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Signing key ids to use for signing operator jwt",
					Required:    false,
				},
				"operator_claims": {
					Type:        framework.TypeMap,
					Description: "Operator claims (jwt.OperatorClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
				"account_server_url": {
					Type:        framework.TypeString,
					Description: "Account server url",
					Required:    false,
				},
				"sync_account_server": {
					Type:        framework.TypeBool,
					Description: "Sync account jwt's with account server",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorIssue,
				},
			},
			HelpSynopsis:    `Manages operator issueing.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListOperatorIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}

}

func (b *NatsBackend) pathAddOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueOperatorParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError + ":" + err.Error()), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueOperatorParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	issue, err := readOperatorIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), nil
	}

	status := getIssueOperatorStatus(ctx, req.Storage, issue)
	return createResponseIssueOperatorData(issue, status)
}

func (b *NatsBackend) pathListOperatorIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	entries, err := listOperatorIssues(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueOperatorParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys and jwt
	err = deleteOperatorIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil

}
func addOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) error {
	// store issue
	issue, err := storeOperatorIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	return refreshOperator(ctx, storage, issue)
}

func refreshOperator(ctx context.Context, storage logical.Storage, issue *IssueOperatorStorage) error {

	// create nkey and signing nkeys
	err := issueOperatorNkeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueOperatorJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	if issue.CreateSystemAccount {
		// create system account
		err := issueSystemAccount(ctx, storage, *issue)
		if err != nil {
			return err
		}
	}
	return nil
}

func readOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) (*IssueOperatorStorage, error) {
	path := getOperatorIssuePath(params.Operator)
	return getFromStorage[IssueOperatorStorage](ctx, storage, path)
}

func listOperatorIssues(ctx context.Context, storage logical.Storage) ([]string, error) {
	path := getOperatorIssuePath("")
	return listIssues(ctx, storage, path)
}

func deleteOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) error {

	// get stored signing keys
	issue, err := readOperatorIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete operator nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
	}
	err = deleteOperatorNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete operator siginig nkeys
	for _, signingKey := range issue.SigningKeys {
		nkey := NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		}
		err := deleteOperatorSigningNkey(ctx, storage, nkey)
		if err != nil {
			return err
		}
	}

	// if generated, delete system account
	if issue.CreateSystemAccount {
		err := deleteUserIssue(ctx, storage, IssueUserParameters{
			Operator: issue.Operator,
			Account:  issue.SystemAccount,
			User:     issue.SystemAccountUser,
		})
		if err != nil {
			return err
		}

		err = deleteAccountIssue(ctx, storage, IssueAccountParameters{
			Operator: issue.Operator,
			Account:  issue.SystemAccount,
		})
		if err != nil {
			return err
		}
	}

	// delete operator jwt
	jwt := JWTParameters{
		Operator: issue.Operator,
	}
	err = deleteOperatorJWT(ctx, storage, jwt)
	if err != nil {
		return err
	}

	// delete operator issue
	path := getOperatorIssuePath(params.Operator)
	return deleteFromStorage(ctx, storage, path)
}

func storeOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) (*IssueOperatorStorage, error) {
	path := getOperatorIssuePath(params.Operator)

	issue, err := getFromStorage[IssueOperatorStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueOperatorStorage{}
	} else {
		// diff current and incomming signing keys
		// delete removed signing keys
		for _, signingKey := range issue.SigningKeys {
			contains := func(a []string, x string) bool {
				for _, n := range a {
					if x == n {
						return true
					}
				}
				return false
			}
			if !contains(params.SigningKeys, signingKey) {
				p := NkeyParameters{
					Operator: params.Operator,
					Signing:  signingKey,
				}
				err := deleteOperatorSigningNkey(ctx, storage, p)
				if err != nil {
					return nil, err
				}
			}
		}

		if issue.CreateSystemAccount {
			// diff current and incomming system account
			// delete removed system account
			if issue.SystemAccount != "" && issue.SystemAccount != params.SystemAccount {

				err := deleteUserIssue(ctx, storage, IssueUserParameters{
					Operator: issue.Operator,
					Account:  issue.SystemAccount,
					User:     issue.SystemAccountUser,
				})
				if err != nil {
					return nil, err
				}

				err = deleteAccountIssue(ctx, storage, IssueAccountParameters{
					Operator: issue.Operator,
					Account:  issue.SystemAccount,
				})
				if err != nil {
					return nil, err
				}
			}
		}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.CreateSystemAccount = params.CreateSystemAccount
	issue.SystemAccount = params.SystemAccount
	issue.SystemAccountUser = params.SystemAccountUser
	if issue.CreateSystemAccount {
		if issue.SystemAccount == "" {
			issue.SystemAccount = "SYS"
		}
		if issue.SystemAccountUser == "" {
			issue.SystemAccountUser = "SYS"
		}
	}
	issue.SigningKeys = params.SigningKeys
	issue.SyncAccountServer = params.SyncAccountServer
	issue.AccountServerURL = params.AccountServerURL
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueOperatorNkeys(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {

	var refreshAccounts bool

	// issue operator nkey
	p := NkeyParameters{
		Operator: issue.Operator,
	}
	stored, err := readOperatorNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addOperatorNkey(ctx, true, storage, p)
		if err != nil {
			return err
		}
		refreshAccounts = true
	}

	// issue operator siginig nkeys
	for _, signingKey := range issue.SigningKeys {
		p := NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		}
		stored, err := readOperatorSigningNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if stored == nil {
			err := addOperatorSigningNkey(ctx, true, storage, p)
			if err != nil {
				return err
			}
			refreshAccounts = true
		}
	}

	if refreshAccounts {
		// force update of all existing accounts
		// so they can use the new operator nkey to sign their jwt
		log.Info().Str("operator", issue.Operator).Msg("managed nkeys modified, all accounts will be updated")
		err = updateAccountIssues(ctx, storage, issue)
		if err != nil {
			log.Err(err).Str("operator", issue.Operator).Msg("failed to update accounts")
			return err
		}
	}

	log.Info().
		Str("operator", issue.Operator).Msgf("nkey created/updated")

	return nil
}

func issueOperatorJWT(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {
	// receive operator nkey and puplic key
	data, err := readOperatorNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
	})
	if err != nil {
		return fmt.Errorf("could not read operator nkey: %s", err)
	}
	operatorKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return err
	}
	operatorPublicKey, err := operatorKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive public key of system account
	sysAccountPublicKey := ""
	if issue.SystemAccount != "" {
		data, err = readAccountNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.SystemAccount,
		})
		if err != nil {
			return fmt.Errorf("could not read system account nkey: %s", err)
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).
				Msgf("system account nkey does not exist: %s - Cannot create jwt.", issue.SystemAccount)
			return nil
		} else {
			sysAccountKeyPair, err := nkeys.FromSeed(data.Seed)
			if err != nil {
				return fmt.Errorf("could not convert system account nkey to kp: %s", err)
			}
			sysAccountPublicKey, err = sysAccountKeyPair.PublicKey()
			if err != nil {
				return fmt.Errorf("could not extract pulic key from system account nkey: %s", err)
			}
		}
	}

	// receive public keys of signing keys
	var signingPublicKeys []string
	for _, signingKey := range issue.SigningKeys {
		data, err := readOperatorSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		})
		if err != nil {
			return err
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).
				Msgf("signing nkey does not exist: %s - Cannot create jwt.", signingKey)
			continue
		}
		signingKeyPair, err := nkeys.FromSeed(data.Seed)
		if err != nil {
			return err
		}

		signingKey, err := signingKeyPair.PublicKey()
		if err != nil {
			return err
		}
		signingPublicKeys = append(signingPublicKeys, signingKey)
	}

	issue.Claims.ClaimsData.Subject = operatorPublicKey
	issue.Claims.ClaimsData.Issuer = operatorPublicKey
	issue.Claims.Operator.SystemAccount = sysAccountPublicKey
	issue.Claims.Operator.SigningKeys = signingPublicKeys
	token, err := issue.Claims.Encode(operatorKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode operator jwt: %s", err)
	}

	// store operator jwt
	err = addOperatorJWT(ctx, true, storage, JWTParameters{
		Operator: issue.Operator,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}

	log.Info().
		Str("operator", issue.Operator).
		Msgf("jwt created/updated")
	return nil
}

func issueSystemAccount(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {

	// create system account jwt and nkey
	err := addAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
		Claims: jwt.AccountClaims{
			Account: jwt.Account{
				Imports: []*jwt.Import{},
				Exports: []*jwt.Export{
					{
						Name:                 "account-monitoring-services",
						Subject:              "$SYS.REQ.ACCOUNT.*.*",
						Type:                 jwt.Service,
						ResponseType:         jwt.ResponseTypeStream,
						AccountTokenPosition: 4,
						Info: jwt.Info{
							Description: `Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO`,
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
					{
						Name:                 "account-monitoring-streams",
						Subject:              "$SYS.ACCOUNT.*.>",
						Type:                 jwt.Stream,
						AccountTokenPosition: 3,
						Info: jwt.Info{
							Description: `Account specific monitoring stream`,
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	// create system account user jwt and nkey
	err = addUserIssue(ctx, storage, IssueUserParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
		User:     issue.SystemAccountUser,
	})
	if err != nil {
		return err
	}

	return nil
}

func updateAccountIssues(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {

	accounts, err := listAccountIssues(ctx, storage, issue.Operator)
	if err != nil {
		return err
	}

	for _, account := range accounts {
		acc, err := readAccountIssue(ctx, storage, IssueAccountParameters{
			Operator: issue.Operator,
			Account:  account,
		})
		if err != nil {
			return err
		}
		if acc == nil {
			return err
		}
		err = refreshAccount(ctx, storage, acc)
		if err != nil {
			return err
		}
	}
	return nil
}

func getOperatorIssuePath(operator string) string {
	return "issue/operator/" + operator
}

func getIssueOperatorStatus(ctx context.Context, storage logical.Storage, issue *IssueOperatorStorage) *IssueOperatorStatus {

	var status IssueOperatorStatus

	// operator status
	nkey, err := readOperatorNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
	})
	if err == nil && nkey != nil {
		status.Operator.Nkey = true
	}
	jwt, err := readOperatorJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
	})
	if err == nil && jwt != nil {
		status.Operator.JWT = true
	}

	// sys account status
	nkey, err = readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
	})
	if err == nil && nkey != nil {
		status.SystemAccount.Nkey = true

	}
	jwt, err = readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
	})
	if err == nil && jwt != nil {
		status.SystemAccount.JWT = true
	}

	// sys account user status
	nkey, err = readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
		User:     issue.SystemAccountUser,
	})
	if err == nil && nkey != nil {
		status.SystemAccountUser.Nkey = true
	}
	jwt, err = readUserJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
		User:     issue.SystemAccountUser,
	})
	if err == nil && jwt != nil {
		status.SystemAccountUser.JWT = true
	}
	return &status
}

func createResponseIssueOperatorData(issue *IssueOperatorStorage, status *IssueOperatorStatus) (*logical.Response, error) {

	data := &IssueOperatorData{
		Operator:            issue.Operator,
		CreateSystemAccount: issue.CreateSystemAccount,
		SystemAccount:       issue.SystemAccount,
		SystemAccountUser:   issue.SystemAccountUser,
		AccountServerURL:    issue.AccountServerURL,
		SyncAccountServer:   issue.SyncAccountServer,
		SigningKeys:         issue.SigningKeys,
		Claims:              issue.Claims,
		Status:              *status,
	}

	rval := map[string]interface{}{}
	err := mapstructure.Decode(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}
