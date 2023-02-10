package common

import "github.com/nats-io/jwt/v2"

func ConvertGenericFields(in *GenericFields) jwt.GenericFields {
	return jwt.GenericFields{
		Tags:    jwt.TagList(in.Tags),
		Type:    jwt.ClaimType(in.Type),
		Version: in.Version,
	}
}

func ConvertClaimsData(in *ClaimsData) jwt.ClaimsData {
	return jwt.ClaimsData{
		Audience:  in.Audience,
		Expires:   in.Expires,
		ID:        in.ID,
		IssuedAt:  in.IssuedAt,
		Issuer:    in.Issuer,
		Name:      in.Name,
		NotBefore: in.NotBefore,
		Subject:   in.Subject,
	}
}
