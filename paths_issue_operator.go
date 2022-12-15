package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
)

type IssueOperatorStorage struct {
	Operator      string             `mapstructure:"operator"`
	SystemAccount string             `mapstructure:"system_account"`
	SigningKeys   []string           `mapstructure:"signing_keys"`
	Claims        jwt.OperatorClaims `mapstructure:"operator_claims"`
}

type IssueOperatorParameters struct {
	Operator      string             `mapstructure:"operator"`
	SystemAccount string             `mapstructure:"system_account"`
	SigningKeys   []string           `mapstructure:"signing_keys"`
	Claims        jwt.OperatorClaims `mapstructure:"operator_claims"`
}

type IssueOperatorData struct {
	Operator      string             `mapstructure:"operator"`
	SystemAccount string             `mapstructure:"system_account"`
	SigningKeys   []string           `mapstructure:"signing_keys"`
	Claims        jwt.OperatorClaims `mapstructure:"operator_claims"`
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
				"system_account": {
					Type:        framework.TypeString,
					Description: "Use nkey id to use as system account",
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

	return createResponseIssueOperatorData(issue)
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

	// create nkey and signing nkeys
	err = issueOperatorNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueOperatorJWT(ctx, storage, *issue)
	if err != nil {
		return err
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

	// delete system account nkey
	// this is only done when no issue did take ownership of the system account
	// if an issue did take ownership of the system account, the system account nkey is deleted when the issue is deleted
	accountIssue, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  issue.SystemAccount,
	})
	if err != nil {
		return err
	}
	if accountIssue == nil {
		// no issue took ownership of the system account nkey
		nkey := NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.SystemAccount,
		}
		err := deleteAccountNkey(ctx, storage, nkey)
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

		// diff current and incomming system account
		if issue.SystemAccount != "" && issue.SystemAccount != params.SystemAccount {

			// delete system account nkey
			// this is only done when no issue did take ownership of the system account
			// if an issue did take ownership of the system account, the system account nkey is deleted when the issue is deleted
			accountIssue, err := readAccountIssue(ctx, storage, IssueAccountParameters{
				Operator: issue.Operator,
				Account:  issue.SystemAccount,
			})
			if err != nil {
				return nil, err
			}
			if accountIssue == nil {
				// no issue took ownership of the system account nkey
				nkey := NkeyParameters{
					Operator: issue.Operator,
					Account:  issue.SystemAccount,
				}
				err := deleteAccountNkey(ctx, storage, nkey)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.SystemAccount = params.SystemAccount
	issue.SigningKeys = params.SigningKeys
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueOperatorNKeys(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {

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
		}
	}

	// make sure system account nkey exists
	// this is a chicken and egg problem
	// the system account nkey is needed to issue the operator jwt
	if issue.SystemAccount != "" {
		data, err := readAccountNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.SystemAccount,
		})
		if err != nil {
			return fmt.Errorf("could not read system account nkey: %s", err)
		}
		if data == nil {
			addAccountNkey(ctx, true, storage, NkeyParameters{
				Operator: issue.Operator,
				Account:  issue.SystemAccount,
			})
			if err != nil {
				return fmt.Errorf("could not create system account nkey: %s", err)
			}
		}
	}

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
	operatorKeyPair, err := convertToKeyPair(data.Seed)
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
			return fmt.Errorf("system account does not exist")
		}
		sysAccountKeyPair, err := convertToKeyPair(data.Seed)
		if err != nil {
			return err
		}

		sysAccountPublicKey, err = sysAccountKeyPair.PublicKey()
		if err != nil {
			return err
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
			return fmt.Errorf("could not read signing key")
		}

		signingKeyPair, err := convertToKeyPair(data.Seed)
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
	return nil
}

func getOperatorIssuePath(operator string) string {
	return "issue/operator/" + operator
}

func createResponseIssueOperatorData(issue *IssueOperatorStorage) (*logical.Response, error) {

	data := &IssueOperatorData{
		Operator:      issue.Operator,
		SystemAccount: issue.SystemAccount,
		SigningKeys:   issue.SigningKeys,
		Claims:        issue.Claims,
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
