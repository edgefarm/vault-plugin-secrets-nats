package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/resolver"
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"

	v1alpha1 "github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/account/v1alpha1"
)

type IssueAccountStorage struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey"`
	Claims        v1alpha1.AccountClaims `json:"claims"`
	Status        IssueAccountStatus     `json:"status"`
}

// IssueAccountParameters is the user facing interface for configuring an account issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueAccountParameters struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey,omitempty"`
	Claims        v1alpha1.AccountClaims `json:"claims,omitempty"`
}

type IssueAccountData struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey"`
	Claims        v1alpha1.AccountClaims `json:"claims"`
	Status        IssueAccountStatus     `json:"status"`
}

type IssueAccountStatus struct {
	Account       IssueStatus         `json:"account"`
	AccountServer AccountServerStatus `json:"accountServer"`
}

type AccountServerStatus struct {
	Synced   bool  `json:"synced"`
	LastSync int64 `json:"lastSync"`
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
				"useSigningKey": {
					Type:        framework.TypeString,
					Description: "Explicitly specified operator signing key to sign the account",
					Required:    false,
				},
				"claims": {
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

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountParameters{}
	json.Unmarshal(jsonString, &params)
	err = addAccountIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingIssueFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountParameters{}
	json.Unmarshal(jsonString, &params)

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

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountParameters{}
	json.Unmarshal(jsonString, &params)

	entries, err := listAccountIssues(ctx, req.Storage, params.Operator)
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

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountParameters{}
	json.Unmarshal(jsonString, &params)

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

	return refreshAccount(ctx, storage, issue)
}

func refreshAccount(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	// create nkey and signing nkeys
	err := issueAccountNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueAccountJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	err = refreshAccountResolverPush(ctx, storage, issue)
	if err != nil {
		return err
	}

	err = updateAccountStatus(ctx, storage, issue)
	if err != nil {
		return err
	}

	_, err = storeAccountIssueUpdate(ctx, storage, issue)
	if err != nil {
		return err
	}

	return nil
}

func readAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(params.Operator, params.Account)
	return getFromStorage[IssueAccountStorage](ctx, storage, path)
}

func listAccountIssues(ctx context.Context, storage logical.Storage, operator string) ([]string, error) {
	path := getAccountIssuePath(operator, "")
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

	// update resolver
	err = refreshAccountResolverDelete(ctx, storage, issue)
	if err != nil {
		return err
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
	for _, signingKey := range issue.Claims.SigningKeys {
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

func storeAccountIssueUpdate(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(issue.Operator, issue.Account)

	err := storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
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
		for _, signingKey := range issue.Claims.SigningKeys {
			contains := func(a []string, x string) bool {
				for _, n := range a {
					if x == n {
						return true
					}
				}
				return false
			}
			if !contains(params.Claims.SigningKeys, signingKey) {
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
	issue.UseSigningKey = params.UseSigningKey
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueAccountNKeys(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	var refreshTheOperator bool
	var refreshUsers bool

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
		err := addAccountNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if issue.Account == DefaultSysAccountName {
			refreshTheOperator = true
		}
		refreshUsers = true
	}

	// issue account siginig nkeys
	for _, signingKey := range issue.Claims.SigningKeys {
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
			err := addAccountSigningNkey(ctx, storage, p)
			if err != nil {
				return err
			}
			refreshUsers = true
		}
	}

	if refreshTheOperator {
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

		err = refreshOperator(ctx, storage, op)
		if err != nil {
			return err
		}
	}

	if refreshUsers {
		// force update of all existing users
		// so they can use the new account nkey to sign their jwt
		log.Info().Str("operator", issue.Operator).Str("account", issue.Account).Msg("managed nkeys modified, all users will be updated")
		err = updateUserIssues(ctx, storage, issue)
		if err != nil {
			log.Err(err).Str("operator", issue.Operator).Msg("failed to update users")
			return err
		}
	}

	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Msgf("nkey created/updated")

	return nil
}

func issueAccountJWT(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {
	// use either operator nkey or signing nkey to
	// sign jwt and add issuer claim
	useSigningKey := issue.UseSigningKey
	var seed []byte
	if useSigningKey == "" {
		data, err := readOperatorNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return fmt.Errorf("could not read operator nkey: %s", err)
		}
		if data == nil {
			log.Error().
				Str("operator", issue.Operator).Str("account", issue.Account).
				Msgf("operator nkey does not exist: %s - Cannot create JWT.", issue.Operator)
			return fmt.Errorf("operator nkey does not exist: %s - Cannot create JWT", issue.Operator)
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
			log.Error().
				Str("operator", issue.Operator).Str("account", issue.Account).
				Msgf("operator signing nkey does not exist: %s - Cannot create JWT.", useSigningKey)
			return fmt.Errorf("operator signing nkey does not exist: %s - Cannot create JWT", useSigningKey)
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
	accountKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive public keys of signing keys
	var signingPublicKeys []string
	for _, signingKey := range issue.Claims.SigningKeys {
		data, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing key")
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).Str("account", issue.Account).
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

	issue.Claims.ClaimsData.Subject = accountPublicKey
	issue.Claims.ClaimsData.Issuer = signingPublicKey
	// TODO: dont know how to handle scopes of signing keys
	issue.Claims.Account.SigningKeys = signingPublicKeys
	natsJwt, err := v1alpha1.Convert(&issue.Claims)
	if err != nil {
		return fmt.Errorf("could not convert claims to nats jwt: %s", err)
	}
	token, err := natsJwt.Encode(signingKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode account jwt: %s", err)
	}

	// store account jwt
	err = addAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}
	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).
		Msgf("jwt created/updated")
	return nil
}

func updateUserIssues(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	users, err := listUserIssues(ctx, storage, IssueUserParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}

	for _, user := range users {
		user, err := readUserIssue(ctx, storage, IssueUserParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			User:     user,
		})
		if err != nil {
			return err
		}
		if user == nil {
			return err
		}
		err = refreshUser(ctx, storage, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func refreshAccountResolverPush(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	return refreshAccountResolver(ctx, storage, issue, "push")
}

func refreshAccountResolverDelete(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	return refreshAccountResolver(ctx, storage, issue, "delete")
}

func refreshAccountResolver(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage, action string) error {
	// read operator issue
	op, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
		Operator: issue.Operator,
	})
	if err != nil {
		return err
	} else if op == nil {
		log.Warn().
			Str("operator", issue.Operator).Str("account", issue.Account).
			Msgf("operator issue does not exist - can't sync account server.")
		return nil
	} else if !op.SyncAccountServer {
		return nil
	} else if op.Claims.AccountServerURL == "" {
		log.Warn().
			Str("operator", issue.Operator).Str("account", issue.Account).
			Msgf("account server url is not set - can't sync account server.")
		return nil
	}

	// read account jwt
	accJWT, err := readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	} else if accJWT == nil {
		log.Warn().Str("operator", issue.Operator).
			Str("account", issue.Account).
			Msg("cannot sync account server: account jwt does not exist")
		return nil
	}

	// read system account user jwt
	sysUserJWT, err := readUserJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		User:     DefaultPushUser,
	})
	if err != nil {
		return err
	} else if sysUserJWT == nil {
		log.Warn().Str("operator", issue.Operator).
			Str("account", issue.Account).
			Msg("cannot sync account server: system account user jwt does not exist")
		return nil
	}

	// read system account user nkey
	sysUserNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		User:     DefaultPushUser,
	})
	if err != nil {
		return err
	} else if sysUserNkey == nil {
		log.Error().Str("operator", issue.Operator).
			Str("account", issue.Account).
			Msg("cannot sync account server: system account user nkey does not exist")
		return nil
	}

	sysUserKp, err := nkeys.FromSeed(sysUserNkey.Seed)
	if err != nil {
		return err
	}

	// connect to nats
	resolver, err := resolver.NewResolver(op.Claims.AccountServerURL, []byte(sysUserJWT.JWT), sysUserKp)
	if err != nil {
		log.Warn().Str("operator", issue.Operator).
			Str("account", issue.Account).
			Err(err).
			Msg("cannot create conection to account server")
		resolver.CloseConnection()
		return nil
	}
	defer resolver.CloseConnection()

	switch {
	case action == "push":
		err = resolver.PushAccount(issue.Account, []byte(accJWT.JWT))
		if err != nil {
			log.Error().Str("operator", issue.Operator).
				Str("account", issue.Account).
				Err(err).
				Msg("cannot sync account server (add)")
			resolver.CloseConnection()
			return nil
		}
	case action == "delete":
		operatorNkey, err := readOperatorNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return err
		} else if operatorNkey == nil {
			log.Warn().Str("operator", issue.Operator).
				Msg("cannot sync account server: operator nkey does not exist")
			return nil
		}
		kp, err := toNkeyData(operatorNkey)
		if err != nil {
			return err
		}
		operatorKeypair, err := nkeys.FromSeed([]byte(kp.Seed))
		if err != nil {
			return err
		}

		// read account jwt
		accNkey, err := readAccountNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
		})
		if err != nil {
			return err
		} else if accJWT == nil {
			log.Warn().Str("operator", issue.Operator).
				Str("account", issue.Account).
				Msg("cannot sync account server: account neky does not exist")
			return nil
		}
		kp, err = toNkeyData(accNkey)
		if err != nil {
			return err
		}
		accountKeyPair, err := nkeys.FromSeed([]byte(kp.Seed))
		if err != nil {
			return err
		}
		accountPubKey, err := accountKeyPair.PublicKey()
		if err != nil {
			return err
		}
		_, err = resolver.DeleteAccounts([]string{accountPubKey}, operatorKeypair)
		if err != nil {
			log.Error().Str("operator", issue.Operator).
				Str("account", issue.Account).
				Err(err).
				Msg("cannot sync account server (delete)")
			resolver.CloseConnection()
			return nil
		}
	}

	// update issue status
	issue.Status.AccountServer.Synced = true
	issue.Status.AccountServer.LastSync = time.Now().Unix()
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
		Claims:        issue.Claims,
		Status:        issue.Status,
	}

	rval := map[string]interface{}{}
	err := stm.StructToMap(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func updateAccountStatus(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	// account status
	nkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}

	if nkey == nil {
		issue.Status.Account.Nkey = false
	} else {
		issue.Status.Account.Nkey = true
	}

	jwt, err := readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})

	if err != nil {
		return err
	}

	if jwt == nil {
		issue.Status.Account.JWT = false
	} else {
		issue.Status.Account.JWT = true
	}

	return nil
}

func IsNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://")
}

func addUserToRevocationList(ctx context.Context, storage logical.Storage, account *IssueAccountStorage, user *IssueUserStorage) error {
	// get user public key
	userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: account.Operator,
		Account:  account.Account,
		User:     user.User,
	})
	if err != nil {
		return err
	} else if userNkey == nil {
		return nil
	}
	kp, err := toNkeyData(userNkey)
	if err != nil {
		return err
	}
	userKeypair, err := nkeys.FromSeed([]byte(kp.Seed))
	if err != nil {
		return err
	}
	userPubKey, err := userKeypair.PublicKey()
	if err != nil {
		return err
	}
	// add user to revocation list and store
	if account.Claims.Revocations == nil {
		account.Claims.Revocations = map[string]int64{}
	}
	account.Claims.Revocations[userPubKey] = time.Now().Unix()
	path := getAccountIssuePath(account.Operator, account.Account)
	err = storeInStorage(ctx, storage, path, &account)
	if err != nil {
		return err
	}
	// reissue account jwt and push by refresing account
	return refreshAccount(ctx, storage, account)
}
