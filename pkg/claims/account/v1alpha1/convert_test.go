package v1alpha1

import (
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

func TestConvert(t *testing.T) {
	assert := assert.New(t)
	claims := AccountClaims{
		Account: Account{
			Imports: []Import{
				{
					Name:         "myimport",
					Subject:      "mysubject",
					Account:      "myaccount",
					Token:        "token",
					LocalSubject: "localsubject",
					Type:         "Stream",
					Share:        true,
				},
			},
			Exports: []Export{
				{
					Name:              "myexport",
					Subject:           "mysubject",
					Type:              "Service",
					TokenReq:          true,
					Revocations:       map[string]int64{"r1": 1675804527, "r2": 1675804526},
					ResponseType:      "Stream",
					ResponseThreshold: "3m0s",
					Latency: &ServiceLatency{
						Sampling: 100,
						Results:  "results",
					},
					AccountTokenPosition: 5,
					Advertise:            true,
					Info: common.Info{
						Description: "mydescription",
						InfoURL:     "myurl",
					},
				},
			},
			Limits: OperatorLimits{
				NatsLimits: common.NatsLimits{
					Subs:    1,
					Data:    2,
					Payload: 3,
				},
				AccountLimits: AccountLimits{
					Imports:         4,
					Exports:         5,
					WildcardExports: true,
					DisallowBearer:  true,
					Conn:            6,
					LeafNodeConn:    7,
				},
				JetStreamLimits: JetStreamLimits{
					MemoryStorage:        8,
					DiskStorage:          9,
					Streams:              10,
					Consumer:             11,
					MaxAckPending:        12,
					MemoryMaxStreamBytes: 13,
					DiskMaxStreamBytes:   14,
					MaxBytesRequired:     true,
				},
			},
			SigningKeys: []string{},
			Revocations: map[string]int64{"r3": 1675804525, "r4": 1675804524},
			DefaultPermissions: common.Permissions{
				Pub: common.Permission{
					Allow: []string{"pub1", "pub2"},
					Deny:  []string{"pub3", "pub4"},
				},
				Sub: common.Permission{
					Allow: []string{"sub5", "sub6"},
					Deny:  []string{"sub7", "sub8"},
				},
				Resp: &common.ResponsePermission{
					MaxMsgs: 100,
					Expires: "5m0s",
				},
			},
			Mappings: map[string][]WeightedMapping{
				"mapping1": {
					{
						Weight:  1,
						Subject: "mysubject1",
						Cluster: "mycluster1",
					},
					{
						Weight:  2,
						Subject: "mysubject2",
						Cluster: "mycluster2",
					},
				},
				"mapping2": {
					{
						Weight:  10,
						Subject: "mysubject10",
						Cluster: "mycluster10",
					},
					{
						Weight:  20,
						Subject: "mysubject20",
						Cluster: "mycluster20",
					},
				},
			},
			Authorization: ExternalAuthorization{
				AuthUsers:       []string{"myauthuser1", "myauthuser2"},
				AllowedAccounts: []string{"myacct10", "myacct20", "*"},
				XKey:            "myxkey",
			},
			Info: common.Info{},
		},
	}

	nats, err := Convert(&claims)
	assert.NoError(err)
	assert.Equal(nats.Imports[0].Name, "myimport")
	assert.Equal(nats.Imports[0].Subject, jwt.Subject("mysubject"))
	assert.Equal(nats.Imports[0].Account, "myaccount")
	assert.Equal(nats.Imports[0].Token, "token")
	assert.Equal(nats.Imports[0].LocalSubject, jwt.RenamingSubject("localsubject"))
	assert.Equal(nats.Imports[0].Type, jwt.ExportType(1))
	assert.Equal(nats.Imports[0].Share, true)
	assert.Len(nats.Imports, 1)

	assert.Equal(nats.Exports[0].Name, "myexport")
	assert.Equal(nats.Exports[0].Subject, jwt.Subject("mysubject"))
	assert.Equal(nats.Exports[0].Type, jwt.ExportType(2))
	assert.Equal(nats.Exports[0].TokenReq, true)
	assert.Equal(nats.Exports[0].Revocations, jwt.RevocationList(map[string]int64{"r1": 1675804527, "r2": 1675804526}))
	assert.Equal(nats.Exports[0].ResponseType, jwt.ResponseType("Stream"))
	assert.Equal(nats.Exports[0].ResponseThreshold, time.Duration(180000000000))
	assert.Equal(nats.Exports[0].Latency.Sampling, jwt.SamplingRate(100))
	assert.Equal(nats.Exports[0].Latency.Results, jwt.Subject("results"))
	assert.Equal(nats.Exports[0].AccountTokenPosition, uint(5))
	assert.Equal(nats.Exports[0].Advertise, true)
	assert.Equal(nats.Exports[0].Info.Description, "mydescription")
	assert.Equal(nats.Exports[0].Info.InfoURL, "myurl")
	assert.Len(nats.Exports, 1)

	assert.Equal(nats.Limits.NatsLimits.Subs, int64(1))
	assert.Equal(nats.Limits.NatsLimits.Data, int64(2))
	assert.Equal(nats.Limits.NatsLimits.Payload, int64(3))
	assert.Equal(nats.Limits.AccountLimits.Imports, int64(4))
	assert.Equal(nats.Limits.AccountLimits.Exports, int64(5))
	assert.Equal(nats.Limits.AccountLimits.WildcardExports, true)
	assert.Equal(nats.Limits.AccountLimits.DisallowBearer, true)
	assert.Equal(nats.Limits.AccountLimits.Conn, int64(6))
	assert.Equal(nats.Limits.AccountLimits.LeafNodeConn, int64(7))
	assert.Equal(nats.Limits.JetStreamLimits.MemoryStorage, int64(8))
	assert.Equal(nats.Limits.JetStreamLimits.DiskStorage, int64(9))
	assert.Equal(nats.Limits.JetStreamLimits.Streams, int64(10))
	assert.Equal(nats.Limits.JetStreamLimits.Consumer, int64(11))
	assert.Equal(nats.Limits.JetStreamLimits.MaxAckPending, int64(12))
	assert.Equal(nats.Limits.JetStreamLimits.MemoryMaxStreamBytes, int64(13))
	assert.Equal(nats.Limits.JetStreamLimits.DiskMaxStreamBytes, int64(14))
	assert.Equal(nats.Limits.JetStreamLimits.MaxBytesRequired, true)

	assert.Equal(nats.Revocations["r3"], int64(1675804525))
	assert.Equal(nats.Revocations["r4"], int64(1675804524))
	assert.Len(nats.Revocations, 2)

	assert.Equal(nats.DefaultPermissions.Pub.Allow, jwt.StringList{"pub1", "pub2"})
	assert.Equal(nats.DefaultPermissions.Pub.Deny, jwt.StringList{"pub3", "pub4"})
	assert.Equal(nats.DefaultPermissions.Sub.Allow, jwt.StringList{"sub5", "sub6"})
	assert.Equal(nats.DefaultPermissions.Sub.Deny, jwt.StringList{"sub7", "sub8"})
	assert.Equal(nats.DefaultPermissions.Resp.Expires, time.Duration(300000000000))
	assert.Equal(nats.DefaultPermissions.Resp.MaxMsgs, int(100))

	assert.Len(nats.Mappings, 2)
	assert.Equal(nats.Mappings["mapping1"][0].Subject, jwt.Subject("mysubject1"))
	assert.Equal(nats.Mappings["mapping1"][0].Cluster, "mycluster1")
	assert.Equal(nats.Mappings["mapping1"][0].Weight, uint8(1))
	assert.Equal(nats.Mappings["mapping1"][1].Subject, jwt.Subject("mysubject2"))
	assert.Equal(nats.Mappings["mapping1"][1].Cluster, "mycluster2")
	assert.Equal(nats.Mappings["mapping1"][1].Weight, uint8(2))
	assert.Len(nats.Mappings["mapping1"], 2)

	assert.Equal(nats.Mappings["mapping2"][0].Subject, jwt.Subject("mysubject10"))
	assert.Equal(nats.Mappings["mapping2"][0].Cluster, "mycluster10")
	assert.Equal(nats.Mappings["mapping2"][0].Weight, uint8(10))
	assert.Equal(nats.Mappings["mapping2"][1].Subject, jwt.Subject("mysubject20"))
	assert.Equal(nats.Mappings["mapping2"][1].Cluster, "mycluster20")
	assert.Equal(nats.Mappings["mapping2"][1].Weight, uint8(20))
	assert.Len(nats.Mappings["mapping2"], 2)

	assert.Equal(nats.Authorization.AuthUsers[0], "myauthuser1")
	assert.Equal(nats.Authorization.AuthUsers[1], "myauthuser2")
	assert.Equal(nats.Authorization.AllowedAccounts[0], "myacct10")
	assert.Equal(nats.Authorization.AllowedAccounts[1], "myacct20")
	assert.Equal(nats.Authorization.AllowedAccounts[2], "*")
	assert.Equal(nats.Authorization.XKey, "myxkey")
}
