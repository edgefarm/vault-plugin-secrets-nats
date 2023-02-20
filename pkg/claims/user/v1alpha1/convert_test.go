package v1alpha1

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestConvert(t *testing.T) {
	assert := assert.New(t)
	claims := &UserClaims{
		User: User{
			UserPermissionLimits: UserPermissionLimits{
				Permissions: common.Permissions{
					Pub: common.Permission{
						Allow: []string{"pub1", "pub2"},
						Deny:  []string{"pub3", "pub4"},
					},
					Sub: common.Permission{
						Allow: []string{"sub1", "sub2"},
						Deny:  []string{"sub3", "sub4"},
					},
					Resp: &common.ResponsePermission{
						MaxMsgs: 100,
						Expires: "5m0s",
					},
				},
				Limits: Limits{
					UserLimits: UserLimits{
						Src: []string{"src1", "src2"},
						Times: []TimeRange{
							{
								Start: "01:15:00",
								End:   "03:15:00",
							},
							{
								Start: "06:15:00",
								End:   "09:15:00",
							},
						},
						Locale: "locale",
					},
					NatsLimits: common.NatsLimits{
						Subs:    1,
						Data:    2,
						Payload: 3,
					},
				},
				BearerToken:            true,
				AllowedConnectionTypes: []string{"STANDARD", "WEBSOCKET"},
			},
			IssuerAccount: "issueraccount",
		},
	}
	a, _ := json.Marshal(claims)
	fmt.Println(string(a))
	nats, err := Convert(claims)
	assert.NoError(err)
	assert.Equal(claims.IssuerAccount, nats.IssuerAccount)
	assert.Len(nats.UserPermissionLimits.Permissions.Pub.Allow, 2)
	assert.Len(nats.UserPermissionLimits.Permissions.Pub.Deny, 2)
	assert.Len(nats.UserPermissionLimits.Permissions.Sub.Allow, 2)
	assert.Len(nats.UserPermissionLimits.Permissions.Sub.Deny, 2)
	assert.Equal(nats.UserPermissionLimits.Pub.Allow, jwt.StringList{"pub1", "pub2"})
	assert.Equal(nats.UserPermissionLimits.Pub.Deny, jwt.StringList{"pub3", "pub4"})
	assert.Equal(nats.UserPermissionLimits.Sub.Allow, jwt.StringList{"sub1", "sub2"})
	assert.Equal(nats.UserPermissionLimits.Sub.Deny, jwt.StringList{"sub3", "sub4"})
	assert.Equal(nats.UserPermissionLimits.Resp.MaxMsgs, int(100))
	assert.Equal(nats.UserPermissionLimits.Resp.Expires, time.Duration(300000000000))
	assert.Equal(nats.UserPermissionLimits.Limits.UserLimits.Src, jwt.CIDRList{"src1", "src2"})
	assert.Equal(nats.UserPermissionLimits.Limits.UserLimits.Times, []jwt.TimeRange{
		{
			Start: "01:15:00",
			End:   "03:15:00",
		},
		{
			Start: "06:15:00",
			End:   "09:15:00",
		},
	})
	assert.Equal(nats.UserPermissionLimits.Limits.UserLimits.Locale, "locale")
	assert.Equal(nats.UserPermissionLimits.Limits.NatsLimits.Subs, int64(1))
	assert.Equal(nats.UserPermissionLimits.Limits.NatsLimits.Data, int64(2))
	assert.Equal(nats.UserPermissionLimits.Limits.NatsLimits.Payload, int64(3))
	assert.Equal(nats.UserPermissionLimits.BearerToken, true)
	assert.Equal(nats.UserPermissionLimits.AllowedConnectionTypes, jwt.StringList{"STANDARD", "WEBSOCKET"})
}
