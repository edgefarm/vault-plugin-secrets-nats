package v1alpha1

import (
	"time"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
)

func convertImports(in *Account, out *jwt.Account) error {
	if in.Imports == nil {
		return nil
	}
	for _, e := range in.Imports {
		nats := &jwt.Import{
			Name:         e.Name,
			Subject:      jwt.Subject(e.Subject),
			Account:      e.Account,
			Token:        e.Token,
			LocalSubject: jwt.RenamingSubject(jwt.Subject(e.LocalSubject)),
			Share:        e.Share,
		}
		t, err := convertExportType(e.Type)
		if err != nil {
			return err
		}
		nats.Type = t
		out.Imports = append(out.Imports, nats)
	}
	return nil
}

func convertExports(in *Account, out *jwt.Account) error {
	if in.Exports == nil {
		return nil
	}
	for _, e := range in.Exports {
		nats := &jwt.Export{
			Name:                 e.Name,
			Subject:              jwt.Subject(e.Subject),
			TokenReq:             e.TokenReq,
			Revocations:          e.Revocations,
			ResponseType:         jwt.ResponseType(e.ResponseType),
			AccountTokenPosition: e.AccountTokenPosition,
			Advertise:            e.Advertise,
			Info: jwt.Info{
				Description: e.Info.Description,
				InfoURL:     e.Info.InfoURL,
			},
		}
		t, err := convertExportType(e.Type)
		if err != nil {
			return err
		}
		nats.Type = t
		if e.Latency != nil {
			nats.Latency = &jwt.ServiceLatency{
				Sampling: jwt.SamplingRate(e.Latency.Sampling),
				Results:  jwt.Subject(e.Latency.Results),
			}
		}
		if e.ResponseThreshold != "" {
			dur, err := time.ParseDuration(e.ResponseThreshold)
			if err != nil {
				return err
			}
			nats.ResponseThreshold = dur
		}
		out.Exports = append(out.Exports, nats)
	}
	return nil
}

func convertLimits(in *Account, out *jwt.Account) {
	out.Limits = jwt.OperatorLimits{
		NatsLimits: jwt.NatsLimits{
			Subs:    in.Limits.NatsLimits.Subs,
			Data:    in.Limits.NatsLimits.Data,
			Payload: in.Limits.NatsLimits.Payload,
		},
		AccountLimits: jwt.AccountLimits{
			Imports:         in.Limits.AccountLimits.Imports,
			Exports:         in.Limits.AccountLimits.Exports,
			WildcardExports: in.Limits.AccountLimits.WildcardExports,
			DisallowBearer:  in.Limits.AccountLimits.DisallowBearer,
			Conn:            in.Limits.AccountLimits.Conn,
			LeafNodeConn:    in.Limits.AccountLimits.LeafNodeConn,
		},
		JetStreamLimits: jwt.JetStreamLimits{
			MemoryStorage:        in.Limits.JetStreamLimits.MemoryStorage,
			DiskStorage:          in.Limits.JetStreamLimits.DiskStorage,
			Streams:              in.Limits.JetStreamLimits.Streams,
			Consumer:             in.Limits.JetStreamLimits.Consumer,
			MaxAckPending:        in.Limits.JetStreamLimits.MaxAckPending,
			MemoryMaxStreamBytes: in.Limits.JetStreamLimits.MemoryMaxStreamBytes,
			DiskMaxStreamBytes:   in.Limits.JetStreamLimits.DiskMaxStreamBytes,
			MaxBytesRequired:     in.Limits.JetStreamLimits.MaxBytesRequired,
		},
	}
}

func convertSigningKeyKind(kind string) jwt.ScopeType {
	switch kind {
	case "user":
		return jwt.UserScopeType
	}
	return jwt.UserScopeType
}

func convertSigningKeys(in *Account, out *jwt.Account) {
	if in.SigningKeys == nil {
		return
	}
	out.SigningKeys = make(map[string]jwt.Scope, len(in.SigningKeys))
	out.SigningKeys.Add(in.SigningKeys...)
}

func convertRevocations(in *Account, out *jwt.Account) {
	if in.Revocations == nil {
		return
	}
	out.Revocations = make(map[string]int64, len(in.Revocations))
	for k, v := range in.Revocations {
		out.Revocations[k] = v
	}
}

func convertDefaultPermissions(in *Account, out *jwt.Account) {
	out.DefaultPermissions = jwt.Permissions{
		Pub: jwt.Permission{
			Allow: jwt.StringList(in.DefaultPermissions.Pub.Allow),
			Deny:  jwt.StringList(in.DefaultPermissions.Pub.Deny),
		},
		Sub: jwt.Permission{
			Allow: jwt.StringList(in.DefaultPermissions.Sub.Allow),
			Deny:  jwt.StringList(in.DefaultPermissions.Sub.Deny),
		},
	}
	if in.DefaultPermissions.Resp != nil {
		out.DefaultPermissions.Resp = &jwt.ResponsePermission{
			MaxMsgs: in.DefaultPermissions.Resp.MaxMsgs,
		}
		if in.DefaultPermissions.Resp.Expires != "" {
			dur, err := time.ParseDuration(in.DefaultPermissions.Resp.Expires)
			if err != nil {
				return
			}
			out.DefaultPermissions.Resp.Expires = dur
		}
	}
}

func convertMappings(in *Account, out *jwt.Account) {
	if in.Mappings == nil {
		return
	}
	out.Mappings = make(map[jwt.Subject][]jwt.WeightedMapping, len(in.Mappings))
	for k, v := range in.Mappings {
		mappings := []jwt.WeightedMapping{}
		for _, m := range v {
			mappings = append(mappings, jwt.WeightedMapping{
				Subject: jwt.Subject(m.Subject),
				Weight:  m.Weight,
				Cluster: m.Cluster,
			})
		}
		out.Mappings[jwt.Subject(k)] = mappings
	}
}

func Convert(claims *AccountClaims) (*jwt.AccountClaims, error) {
	nats := &jwt.AccountClaims{
		Account: jwt.Account{
			Info: jwt.Info{
				Description: claims.Description,
				InfoURL:     claims.InfoURL,
			},
		},
	}
	err := convertImports(&claims.Account, &nats.Account)
	if err != nil {
		return nil, err
	}
	err = convertExports(&claims.Account, &nats.Account)
	if err != nil {
		return nil, err
	}
	convertLimits(&claims.Account, &nats.Account)
	convertSigningKeys(&claims.Account, &nats.Account)
	convertRevocations(&claims.Account, &nats.Account)
	convertDefaultPermissions(&claims.Account, &nats.Account)
	convertMappings(&claims.Account, &nats.Account)
	nats.ClaimsData = common.ConvertClaimsData(&claims.ClaimsData)
	nats.GenericFields = common.ConvertGenericFields(&claims.GenericFields)
	return nats, nil
}
