/*
 * Copyright 2018 The NATS Authors
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
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

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
		// todo: add logging
		// report.AddError("failed to parse response: %v data: %s", err, string(resp.Data))
	} else if srvName := serverResp.Server.Name; srvName == "" {
		// todo: add logging
		// report.AddError("server responded without server name in info: %s", string(resp.Data))
	} else if err := serverResp.Error; err != nil {
		// todo: add logging
		// report.AddError("server %s responded with error: %s", srvName, err.Description)
	} else if data := serverResp.Data; data == nil {
		// todo: add logging
		// report.AddError("server %s responded without data: %s", srvName, string(resp.Data))
	} else {
		return true, srvName, data
	}
	return false, "", nil
}

func isValidURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	supported := []string{"http", "https", "nats"}

	ok := false
	for _, v := range supported {
		if scheme == v {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	return true
}

func multiRequest(nc *nats.Conn, subject string, reqData []byte, respHandler func(srv string, data interface{})) int {
	ib := nats.NewInbox()
	sub, err := nc.SubscribeSync(ib)
	if err != nil {
		// todo: add logging
		// report.AddError("failed to subscribe to response subject: %v", err)
		return 0
	}
	if err := nc.PublishRequest(subject, ib, reqData); err != nil {
		// todo: add logging
		// report.AddError("failed to %s: %v", operation, err)
		return 0
	}
	responses := 0
	now := time.Now()
	start := now
	end := start.Add(time.Second)
	for ; end.After(now); now = time.Now() { // try with decreasing timeout until we dont get responses
		if resp, err := sub.NextMsg(end.Sub(now)); err != nil {
			if err != nats.ErrTimeout || responses == 0 {
				// todo: add logging
				// report.AddError("failed to get response to %s: %v", operation, err)
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

func isNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://")
}

func CreateConnection(url string, userJWT []byte, userKp nkeys.KeyPair) (*nats.Conn, error) {
	if !isValidURL(url) {
		return nil, fmt.Errorf("invalid url: %s", url)
	}

	if !isNatsUrl(url) {
		return nil, fmt.Errorf("invalid url: %s, currently only nats urls are supported", url)
	}

	nats.NewInbox()
	getOpt := func(theJWT string, kp nkeys.KeyPair) nats.Option {
		return nats.UserJWT(
			func() (string, error) {
				return theJWT, nil
			}, func(nonce []byte) ([]byte, error) {
				return kp.Sign(nonce)
			})
	}

	return nats.Connect(url, createDefaultToolOptions("nsc_push", getOpt(string(userJWT), userKp))...)
	// if err != nil {
	// 	return nil, err
	// }
	// defer nc.Close()
	// return nc, nil
}

func DeleteAccounts(nc *nats.Conn, acc []string, operatorKp nkeys.KeyPair) (int, error) {
	defer operatorKp.Wipe()
	pub, err := operatorKp.PublicKey()
	if err != nil {
		return 0, err
	}

	claim := jwt.NewGenericClaims(pub)
	claim.Data["accounts"] = acc

	pruneJwt, err := claim.Encode(operatorKp)
	if err != nil {
		return 0, err
		// subPrune.AddError("Could not encode delete request (err:%v)", err)
	}
	respPrune := multiRequest(nc, "$SYS.REQ.CLAIMS.DELETE", []byte(pruneJwt),
		func(srv string, data interface{}) {
			if _, ok := data.(map[string]interface{}); ok {
				// subPrune.AddOK("pruned nats-server %s: %s", srv, data["message"])
			} else {
				// subPrune.AddOK("pruned nats-server %s: %v", srv, data)
			}
		})

	return respPrune, nil

}

func PushAccount(nc *nats.Conn, accountJWT []byte) error {
	resp := multiRequest(nc, "$SYS.REQ.CLAIMS.UPDATE", accountJWT,
		func(srv string, data interface{}) {
			if _, ok := data.(map[string]interface{}); ok {
				// todo: add logging
				// subAcc.AddOK("pushed %q to nats-server %s: %s", v, srv, data["message"])
			} else {
				// todo: add logging
				// subAcc.AddOK("pushed %q to nats-server %s: %v", v, srv, data)
			}
		})
	if resp == 0 {
		return fmt.Errorf("no response from server")
	}
	return nil
}

func createDefaultToolOptions(name string, o ...nats.Option) []nats.Option {
	connectTimeout := 5 * time.Second
	totalWait := 10 * time.Minute
	reconnectDelay := 2 * time.Second

	opts := []nats.Option{nats.Name(name)}
	opts = append(opts, nats.Timeout(connectTimeout))
	// todo: add tls
	// opts = append(opts, rootCAsNats)
	// opts = append(opts, tlsKeyNats)
	// opts = append(opts, tlsCertNats)
	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		if err != nil {
			// todo: add logging
			// ctx.CurrentCmd().Printf("Disconnected: error: %v\n", err)
		}
		if nc.Status() == nats.CLOSED {
			return
		}
		// todo: add logging
		// ctx.CurrentCmd().Printf("Disconnected: will attempt reconnects for %.0fm", totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		// todo: add logging
		// ctx.CurrentCmd().Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		if nc.Status() == nats.CLOSED {
			return
		}
		// todo: add logging
		// ctx.CurrentCmd().Printf("Exiting, no servers available, or connection closed")
	}))
	opts = append(opts, o...)
	return opts
}

func sendDeleteRequest(nc *nats.Conn, deleteList []string, respList int) {

}
