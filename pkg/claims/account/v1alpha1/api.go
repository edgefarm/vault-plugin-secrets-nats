/*
Copyright 2023 The EdgeFarm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	user "github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/nats-io/jwt/v2"
)

// +kubebuilder:object:generate=true
type AccountClaims struct {
	common.ClaimsData `json:",inline"`
	Account           `json:"account,omitempty"`
}

// Account holds account specific claims data
type Account struct {
	Imports              []Import                     `json:"imports,omitempty"`
	Exports              []Export                     `json:"exports,omitempty"`
	Limits               OperatorLimits               `json:"limits,omitempty"`
	SigningKeys          []string                     `json:"signingKeys,omitempty"`
	Revocations          map[string]int64             `json:"revocations,omitempty"`
	DefaultPermissions   common.Permissions           `json:"defaultPermissions,omitempty"`
	Mappings             map[string][]WeightedMapping `json:"mappings,omitempty"`
	common.Info          `json:",inline"`
	common.GenericFields `json:",inline"`
}

type WeightedMapping struct {
	Subject string `json:"subject"`
	Weight  uint8  `json:"weight,omitempty"`
	Cluster string `json:"cluster,omitempty"`
}

type Identity struct {
	ID    string `json:"id,omitempty"`
	Proof string `json:"proof,omitempty"`
}

type OperatorLimits struct {
	common.NatsLimits     `json:",inline"`
	AccountLimits         `json:",inline"`
	JetStreamLimits       `json:",inline"`
	JetStreamTieredLimits `json:"tieredLimits,omitempty"`
}

type JetStreamTieredLimits map[string]JetStreamLimits

type JetStreamLimits struct {
	MemoryStorage        int64 `json:"memStorage,omitempty"`         // Max number of bytes stored in memory across all streams. (0 means disabled)
	DiskStorage          int64 `json:"diskStorage,omitempty"`        // Max number of bytes stored on disk across all streams. (0 means disabled)
	Streams              int64 `json:"streams,omitempty"`            // Max number of streams
	Consumer             int64 `json:"consumer,omitempty"`           // Max number of consumers
	MaxAckPending        int64 `json:"maxAckPending,omitempty"`      // Max ack pending of a Stream
	MemoryMaxStreamBytes int64 `json:"memMaxStreamBytes,omitempty"`  // Max bytes a memory backed stream can have. (0 means disabled/unlimited)
	DiskMaxStreamBytes   int64 `json:"diskMaxStreamBytes,omitempty"` // Max bytes a disk backed stream can have. (0 means disabled/unlimited)
	MaxBytesRequired     bool  `json:"maxBytesRequired,omitempty"`   // Max bytes required by all Streams
}

type AccountLimits struct {
	Imports         int64 `json:"imports,omitempty"`         // Max number of imports
	Exports         int64 `json:"exports,omitempty"`         // Max number of exports
	WildcardExports bool  `json:"wildcardExports,omitempty"` // Are wildcards allowed in exports
	DisallowBearer  bool  `json:"disallowBearer,omitempty"`  // User JWT can't be bearer token
	Conn            int64 `json:"conn,omitempty"`            // Max number of active connections
	LeafNodeConn    int64 `json:"leafNodeConn,omitempty"`    // Max number of active leaf node connections
}

func convertExportType(t string) (jwt.ExportType, error) {
	switch t {
	case "Stream":
		return jwt.Stream, nil
	case "Service":
		return jwt.Service, nil
	case "Unknown":
		return jwt.Unknown, nil
	default:
		return -1, fmt.Errorf("invalid export type")
	}
}

// Import describes a mapping from another account into this one
type Import struct {
	Name         string `json:"name,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Account      string `json:"account,omitempty"`
	Token        string `json:"token,omitempty"`
	LocalSubject string `json:"localSubject,omitempty"`
	Type         string `json:"type,omitempty"`
	Share        bool   `json:"share,omitempty"`
}

type Export struct {
	Name                 string           `json:"name,omitempty"`
	Subject              string           `json:"subject,omitempty"`
	Type                 string           `json:"type,omitempty"`
	TokenReq             bool             `json:"tokenReq,omitempty"`
	Revocations          map[string]int64 `json:"revocations,omitempty"`
	ResponseType         string           `json:"responseType,omitempty"`
	ResponseThreshold    string           `json:"responseThreshold,omitempty"`
	Latency              *ServiceLatency  `json:"serviceLatency,omitempty"`
	AccountTokenPosition uint             `json:"accountTokenPosition,omitempty"`
	Advertise            bool             `json:"advertise,omitempty"`
	common.Info          `json:",inline"`
}

type ServiceLatency struct {
	// needs to be converted ot SamplingRate
	Sampling int `json:"sampling"`
	// needs to be converted to Subject
	Results string `json:"results"`
}

type UserScope struct {
	// needs to be converted to ScopeType
	Kind     string                    `json:"kind"`
	Key      string                    `json:"key"`
	Role     string                    `json:"role"`
	Template user.UserPermissionLimits `json:"template"`
}
