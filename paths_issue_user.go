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

type IssueUserStorage struct {
	Operator      string          `mapstructure:"operator"`
	Account       string          `mapstructure:"account"`
	User          string          `mapstructure:"user"`
	UseSigningKey string          `mapstructure:"use_signing_key"`
	Claims        jwt.UserClaims  `mapstructure:"user_claims"`
	Status        IssueUserStatus `mapstructure:"status"`
}

type IssueUserParameters struct {
	Operator      string         `mapstructure:"operator"`
	Account       string         `mapstructure:"account"`
	User          string         `mapstructure:"user"`
	UseSigningKey string         `mapstructure:"use_signing_key"`
	Claims        jwt.UserClaims `mapstructure:"user_claims"`
}

type IssueUserData struct {
	Operator      string          `mapstructure:"operator"`
	Account       string          `mapstructure:"account"`
	User          string          `mapstructure:"user"`
	UseSigningKey string          `mapstructure:"use_signing_key"`
	Claims        jwt.UserClaims  `mapstructure:"user_claims"`
	Status        IssueUserStatus `mapstructure:"status"`
}

type IssueUserStatus struct {
	User IssueStatus `mapstructure:"user"`
}

func pathUserIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"user": {
					Type:        framework.TypeString,
					Description: "user identifier",
					Required:    false,
				},
				"use_signing_key": {
					Type:        framework.TypeString,
					Description: "signing key identifier",
					Required:    false,
				},
				"user_claims": {
					Type:        framework.TypeMap,
					Description: "User claims (jwt.UserClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserIssue,
				},
			},
			HelpSynopsis:    `Manages user cmd's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListUserIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	issue, err := readUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), nil
	}

	return createResponseIssueUserData(issue)
}

func (b *NatsBackend) pathListUserIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = mapstructure.Decode(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys and jwt
	err = deleteUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {
	// store issue
	issue, err := storeUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	return refreshUser(ctx, storage, issue)
}

func refreshUser(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) error {

	// create nkey and signing nkeys
	err := issueUserNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueUserJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create creds
	err = issueUserCreds(ctx, storage, *issue)
	if err != nil {
		return err
	}

	updateUserStatus(ctx, storage, issue)

	_, err = storeUserIssueUpdate(ctx, storage, issue)
	if err != nil {
		return err
	}

	if issue.User == DefaultPushUser {
		// force update of operator
		// so he gets updates from sys account
		op, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return err
		} else if op == nil {
			log.Warn().Str("operator", issue.Operator).Str("account", issue.Account).Msg("cannot refresh operator: operator issue does not exist")
			return nil
		}

		err = refreshAccountResolvers(ctx, storage, op)
		if err != nil {
			return err
		}
	}

	// // store issue
	// issue, err = storeUserIssue(ctx, storage, issue.)
	// if err != nil {
	// 	return err
	// }
	return nil
}

func readUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)
	return getFromStorage[IssueUserStorage](ctx, storage, path)
}

func listUserIssues(ctx context.Context, storage logical.Storage, params IssueUserParameters) ([]string, error) {
	path := getUserIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func deleteUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {

	// get stored signing keys
	issue, err := readUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete user nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	err = deleteUserNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete user jwt
	jwt := JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	err = deleteUserJWT(ctx, storage, jwt)
	if err != nil {
		return err
	}

	// delete user creds
	creds := CredsParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	err = deleteUserCreds(ctx, storage, creds)
	if err != nil {
		return err
	}

	// delete user issue
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)
	return deleteFromStorage(ctx, storage, path)
}

func storeUserIssueUpdate(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) (*IssueUserStorage, error) {
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)

	err := storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func storeUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)

	issue, err := getFromStorage[IssueUserStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueUserStorage{}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.User = params.User
	issue.UseSigningKey = params.UseSigningKey
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueUserNKeys(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {
	// issue user nkey
	p := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	stored, err := readUserNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addUserNkey(ctx, true, storage, p)
		if err != nil {
			return err
		}
	}
	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
		Msgf("nkey created/updated")
	return nil
}

func issueUserJWT(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {

	// use either operator nkey or signing nkey
	// to sign jwt and add issuer claim
	useSigningKey := issue.UseSigningKey
	var seed []byte
	if useSigningKey == "" {
		data, err := readAccountNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
		})
		if err != nil {
			return fmt.Errorf("could not read operator nkey: %s", err)
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
				Msgf("account nkey does not exist: %s - Cannot create jwt.", issue.Account)
			return nil
		}
		seed = data.Seed
	} else {
		data, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  useSigningKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing nkey: %s", err)
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
				Msgf("account signing nkey does not exist: %s - Cannot create jwt.", useSigningKey)
			return nil
		}
		seed = data.Seed
	}
	signingKeyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return err
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive user nkey puplic key
	// to add subject
	data, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return fmt.Errorf("could not read user nkey: %s", err)
	}
	if data == nil {
		return fmt.Errorf("user nkey does not exist")
	}
	userKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return err
	}
	userPublicKey, err := userKeyPair.PublicKey()
	if err != nil {
		return err
	}

	issue.Claims.ClaimsData.Subject = userPublicKey
	issue.Claims.ClaimsData.Issuer = signingPublicKey
	token, err := issue.Claims.Encode(signingKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode jwt: %s", err)
	}

	// store jwt
	err = addUserJWT(ctx, true, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}

	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
		Msgf("jwt created/updated")
	return nil
}

func issueUserCreds(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {

	// receive user nkey seed
	// to add to creds file
	userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return fmt.Errorf("could not read user nkey: %s", err)
	}
	if userNkey == nil {
		return fmt.Errorf("user nkey does not exist")
	}
	userKeyPair, err := nkeys.FromSeed(userNkey.Seed)
	if err != nil {
		return err
	}
	seed, err := userKeyPair.Seed()
	if err != nil {
		return err
	}

	// receive jwt
	userJwt, err := readUserJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return fmt.Errorf("could not read user jwt: %s", err)
	}
	if userJwt == nil {
		log.Warn().
			Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
			Msgf("user jwt does not exist: %s - Cannot create creds.", issue.Account)
		return nil
	}

	// format creds
	creds, err := jwt.FormatUserConfig(userJwt.JWT, seed)
	if err != nil {
		return fmt.Errorf("could not format user creds: %s", err)
	}

	// store creds
	err = addUserCreds(ctx, true, storage, CredsParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
		CredsStorage: CredsStorage{
			Creds: string(creds),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func getUserIssuePath(operator string, account string, user string) string {
	return "issue/operator/" + operator + "/account/" + account + "/user/" + user
}

func createResponseIssueUserData(issue *IssueUserStorage) (*logical.Response, error) {

	data := &IssueUserData{
		Operator:      issue.Operator,
		Account:       issue.Account,
		User:          issue.User,
		UseSigningKey: issue.UseSigningKey,
		Claims:        issue.Claims,
		Status:        issue.Status,
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

func updateUserStatus(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) {

	// account status
	nkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err == nil && nkey != nil {
		issue.Status.User.Nkey = true
	} else {
		issue.Status.User.Nkey = false
	}
	jwt, err := readUserJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err == nil && jwt != nil {
		issue.Status.User.JWT = true
	} else {
		issue.Status.User.JWT = false
	}
}
