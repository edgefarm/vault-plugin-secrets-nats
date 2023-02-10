/*
 * Copyright 2023 The EdgeFarm Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package resolver

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

func (r *Resolver) multiRequest(subject string, operation string, reqData []byte, respHandler func(srv string, data interface{})) int {
	ib := nats.NewInbox()
	sub, err := r.nc.SubscribeSync(ib)
	if err != nil {
		log.Error().Msgf("resolver: failed to subscribe to response subject: %v", err)
		return 0
	}
	if err := r.nc.PublishRequest(subject, ib, reqData); err != nil {
		log.Error().Msgf("resolver: failed to %s: %v", operation, err)
		return 0
	}
	responses := 0
	now := time.Now()
	start := now
	end := start.Add(time.Second)
	for ; end.After(now); now = time.Now() { // try with decreasing timeout until we dont get responses
		if resp, err := sub.NextMsg(end.Sub(now)); err != nil {
			if err != nats.ErrTimeout || responses == 0 {
				log.Error().Msgf("resolver: failed to get response to %s: %v", operation, err)
			}
		} else if ok, srv, data := processResponse(resp); ok {
			respHandler(srv, data)
			responses++
			continue
		}
		break
	}
	return responses
}

func (r *Resolver) DeleteAccounts(acc []string, operatorKp nkeys.KeyPair) (int, error) {
	defer operatorKp.Wipe()
	pub, err := operatorKp.PublicKey()
	if err != nil {
		return 0, err
	}

	claim := jwt.NewGenericClaims(pub)
	claim.Data["accounts"] = acc

	pruneJwt, err := claim.Encode(operatorKp)
	if err != nil {
		log.Error().Msgf("Could not encode delete request (err:%v)", err)
		return 0, err
	}
	respPrune := r.multiRequest(ClaimsDeleteSubject, "delete", []byte(pruneJwt),
		func(srv string, data interface{}) {
			if dataMap, ok := data.(map[string]interface{}); ok {
				log.Info().Msgf("pruned nats-server %s: %s", srv, dataMap["message"])
			} else {
				log.Info().Msgf("pruned nats-server %s: %v", srv, data)
			}
		})

	return respPrune, nil
}

func (r *Resolver) PushAccount(accountName string, accountJWT []byte) error {
	resp := r.multiRequest(ClaimsUpdateSubject, "create", accountJWT,
		func(srv string, data interface{}) {
			if dataMap, ok := data.(map[string]interface{}); ok {
				log.Info().Msgf("pushed %q to nats-server %s: %s", accountName, srv, dataMap["message"])
			} else {
				log.Info().Msgf("pushed %q to nats-server %s: %v", accountName, srv, data)
			}
		})
	if resp == 0 {
		return fmt.Errorf("no response from server")
	}
	return nil
}

func processResponse(resp *nats.Msg) (bool, string, interface{}) {
	// ServerInfo copied from nats-server, refresh as needed. Error and Data are mutually exclusive
	serverResp := struct {
		Server *struct {
			Name      string    `json:"name"`
			Host      string    `json:"host"`
			ID        string    `json:"id"`
			Cluster   string    `json:"cluster,omitempty"`
			Version   string    `json:"ver"`
			Seq       uint64    `json:"seq"`
			JetStream bool      `json:"jetstream"`
			Time      time.Time `json:"time"`
		} `json:"server"`
		Error *struct {
			Description string `json:"description"`
			Code        int    `json:"code"`
		} `json:"error"`
		Data interface{} `json:"data"`
	}{}
	if err := json.Unmarshal(resp.Data, &serverResp); err != nil {
		log.Error().Msgf("resolver: failed to parse response: %v data: %s", err, string(resp.Data))
	} else if srvName := serverResp.Server.Name; srvName == "" {
		log.Error().Msgf("resolver: server responded without server name in info: %s", string(resp.Data))
	} else if err := serverResp.Error; err != nil {
		log.Error().Msgf("resolver: server %s responded with error: %s", srvName, err.Description)
	} else if data := serverResp.Data; data == nil {
		log.Error().Msgf("resolver: server %s responded without data: %s", srvName, string(resp.Data))
	} else {
		return true, srvName, data
	}
	return false, "", nil
}
