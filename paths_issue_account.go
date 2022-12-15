package natsbackend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/jwt/v2"
)

type IssueAccountStorage struct {
	Operator      string            `mapstructure:"operator"`
	Account       string            `mapstructure:"account"`
	UseSigningKey string            `mapstructure:"use_signing_key"`
	SigningKeys   []string          `mapstructure:"signing_keys"`
	Claims        jwt.AccountClaims `mapstructure:"account_claims"`
}

type IssueAccountParameters struct {
	Operator      string            `mapstructure:"operator"`
	Account       string            `mapstructure:"account"`
	UseSigningKey string            `mapstructure:"use_signing_key"`
	SigningKeys   []string          `mapstructure:"signing_keys"`
	Claims        jwt.AccountClaims `mapstructure:"account_claims"`
}

type IssueAccountData struct {
	Operator      string            `mapstructure:"operator"`
	Account       string            `mapstructure:"account"`
	UseSigningKey string            `mapstructure:"use_signing_key"`
	SigningKeys   []string          `mapstructure:"signing_keys"`
	Claims        jwt.AccountClaims `mapstructure:"account_claims"`
}

func pathAccountIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"use_signing_key": {
					Type:        framework.TypeString,
					Description: "Explicitly specified operator signing key to sign the account",
					Required:    false,
				},
				"signing_keys": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Signing keys to use for signing account jwt",
					Required:    false,
				},
				"account_claims": {
					Type:        framework.TypeMap,
					Description: "Account claims (jwt.AccountClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountIssue,
				},
			},
			HelpSynopsis:    `Manages account Issue's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountIssue,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	issue, err := readAccountIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), nil
	}

	return createResponseIssueAccountData(issue)
}

func (b *NatsBackend) pathListAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listAccountIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys and jwt
	err = deleteAccountIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) error {
	// store issue
	issue, err := storeAccountIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	// create nkey and signing nkeys
	err = issueAccountNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueAccountJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	return nil
}

func readAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(params.Operator, params.Account)
	return getFromStorage[IssueAccountStorage](ctx, storage, path)
}

func listAccountIssues(ctx context.Context, storage logical.Storage, params IssueAccountParameters) ([]string, error) {
	path := getAccountIssuePath(params.Operator, "")
	return listIssues(ctx, storage, path)
}

func deleteAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) error {

	// get stored signing keys
	issue, err := readAccountIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete account nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	err = deleteAccountNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete account siginig nkeys
	for _, signingKey := range issue.SigningKeys {
		nkey := NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		}
		err := deleteAccountSigningNkey(ctx, storage, nkey)
		if err != nil {
			return err
		}
	}

	// delete account jwt
	jwt := JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	err = deleteAccountJWT(ctx, storage, jwt)
	if err != nil {
		return err
	}

	// delete account issue
	path := getAccountIssuePath(issue.Operator, issue.Account)
	return deleteFromStorage(ctx, storage, path)
}

func storeAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(params.Operator, params.Account)

	issue, err := getFromStorage[IssueAccountStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueAccountStorage{}
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
					Account:  params.Account,
					Signing:  signingKey,
				}
				err := deleteAccountSigningNkey(ctx, storage, p)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.SigningKeys = params.SigningKeys
	issue.UseSigningKey = params.UseSigningKey
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueAccountNKeys(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	// issue account nkey
	p := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	stored, err := readAccountNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addAccountNkey(ctx, true, storage, p)
		if err != nil {
			return err
		}
	}

	// issue account siginig nkeys
	for _, signingKey := range issue.SigningKeys {
		p := NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		}
		stored, err := readAccountSigningNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if stored == nil {
			err := addAccountSigningNkey(ctx, true, storage, p)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func issueAccountJWT(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	// use either operator nkey or signing nkey
	// to sign jwt and add issuer claim
	useSigningKey := issue.UseSigningKey
	var seed string
	if useSigningKey == "" {
		data, err := readOperatorNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return fmt.Errorf("could not read operator nkey: %s", err)
		}
		if data == nil {
			return fmt.Errorf("operator nkey does not exist")
		}
		seed = data.Seed
	} else {
		data, err := readOperatorSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Signing:  useSigningKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing nkey: %s", err)
		}
		if data == nil {
			return fmt.Errorf("signing nkey does not exist")
		}
		seed = data.Seed
	}
	signingKeyPair, err := convertToKeyPair(seed)
	if err != nil {
		return err
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive account nkey puplic key
	// to add subject
	data, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return fmt.Errorf("could not read account nkey: %s", err)
	}
	if data == nil {
		return fmt.Errorf("account nkey does not exist")
	}
	accountKeyPair, err := convertToKeyPair(data.Seed)
	if err != nil {
		return err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive public keys of signing keys
	var signingPublicKeys []string
	for _, signingKey := range issue.SigningKeys {
		data, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing key")
		}
		if data == nil {
			return fmt.Errorf("signing key does not exist")
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

	issue.Claims.ClaimsData.Subject = accountPublicKey
	issue.Claims.ClaimsData.Issuer = signingPublicKey
	// TODO: dont know how to handle scopes of signing keys
	// issue.Claims.Account.SigningKeys = signingPublicKeys
	token, err := issue.Claims.Encode(signingKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode account jwt: %s", err)
	}

	// store account jwt
	err = addAccountJWT(ctx, true, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func getAccountIssuePath(operator string, account string) string {
	return "issue/operator/" + operator + "/account/" + account
}

func createResponseIssueAccountData(issue *IssueAccountStorage) (*logical.Response, error) {

	data := &IssueAccountData{
		Operator:      issue.Operator,
		Account:       issue.Account,
		UseSigningKey: issue.UseSigningKey,
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
