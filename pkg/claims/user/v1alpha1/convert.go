package v1alpha1

import (
	"fmt"
	"time"

	"golang.org/x/exp/slices"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
)

func convertNatsLimits(in *User, out *jwt.User) {
	out.NatsLimits.Data = in.NatsLimits.Data
	out.NatsLimits.Payload = in.NatsLimits.Payload
	out.NatsLimits.Subs = in.NatsLimits.Subs
}

func convertUserLimits(in *User, out *jwt.User) {
	out.UserLimits.Locale = in.UserLimits.Locale
	out.UserLimits.Src = jwt.CIDRList(jwt.TagList(in.UserLimits.Src))
	for _, e := range in.UserLimits.Times {
		out.UserLimits.Times = append(out.UserLimits.Times, jwt.TimeRange{
			Start: e.Start,
			End:   e.End,
		})
	}
}

func convertUserPermissionLimits(in *User, out *jwt.User) error {
	out.UserPermissionLimits.Pub.Allow = in.UserPermissionLimits.Pub.Allow
	out.UserPermissionLimits.Pub.Deny = in.UserPermissionLimits.Pub.Deny
	out.UserPermissionLimits.Sub.Allow = in.UserPermissionLimits.Sub.Allow
	out.UserPermissionLimits.Sub.Deny = in.UserPermissionLimits.Sub.Deny
	if in.UserPermissionLimits.Resp != nil {
		out.UserPermissionLimits.Resp = &jwt.ResponsePermission{}
		out.UserPermissionLimits.Resp.MaxMsgs = in.UserPermissionLimits.Resp.MaxMsgs
		dur, err := time.ParseDuration(in.UserPermissionLimits.Resp.Expires)
		if err != nil {
			return err
		}
		out.UserPermissionLimits.Resp.Expires = dur
	}
	out.UserPermissionLimits.BearerToken = in.UserPermissionLimits.BearerToken
	err := checkAllowedConnectionTypes(in.UserPermissionLimits.AllowedConnectionTypes)
	if err != nil {
		return err
	}
	out.UserPermissionLimits.AllowedConnectionTypes = jwt.StringList(in.UserPermissionLimits.AllowedConnectionTypes)
	return nil
}

func checkAllowedConnectionTypes(t []string) error {
	allowed := []string{
		"STANDARD",
		"WEBSOCKET",
		"LEAFNODE",
		"LEAFNODE_WS",
		"MQTT",
		"MQTT_WS",
	}
	for _, e := range t {
		if !slices.Contains(allowed, e) {
			return fmt.Errorf("invalid connection type: %s", e)
		}
	}
	return nil
}

func Convert(claims *UserClaims) (*jwt.UserClaims, error) {
	nats := &jwt.UserClaims{
		User: jwt.User{
			IssuerAccount: claims.IssuerAccount,
		},
	}
	err := convertUserPermissionLimits(&claims.User, &nats.User)
	if err != nil {
		return nil, err
	}
	convertUserLimits(&claims.User, &nats.User)
	convertNatsLimits(&claims.User, &nats.User)
	nats.ClaimsData = common.ConvertClaimsData(&claims.ClaimsData)
	nats.GenericFields = common.ConvertGenericFields(&claims.GenericFields)
	return nats, nil
}
