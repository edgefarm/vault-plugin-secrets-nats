package natsbackend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Parameters[T any] struct {
	Name        string `json:"name" mapstructure:"name"`
	TokenClaims T      `json:"claims" mapstructure:"claims"`
	TokenID     string `json:"token_id" mapstructure:"token_id"`
	NKeyID      string `json:"nkey_id" mapstructure:"nkey_id"`
}

func operatorCmdPath() string {
	return "cmd/operator"
}

func accountCmdPath(account string) string {
	return "cmd/operator/account/" + account
}

func userCmdPath(account, user string) string {
	return "cmd/operator/account/" + account + "/user/" + user
}

// pathCmd extends the Vault API with a `/cmd/<category>`
// endpoint for the natsBackend.
func pathCmd(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		pathCmdOperator(b),
		pathCmdAccount(b),
		pathCmdUser(b),
		{
			Pattern: "cmd/operator/account/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathCmdAccountList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
		{
			Pattern: "cmd/operator/account/" + framework.GenericNameRegex(cmdUserFieldParams[UserAccountName]) + "/user/?$",
			Fields: map[string]*framework.FieldSchema{
				cmdUserFieldParams[UserAccountName]: {
					Type:        framework.TypeString,
					Description: "Account Name",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathCmdUserList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}
