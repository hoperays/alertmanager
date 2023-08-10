// Copyright 2023 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package feishubot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	commoncfg "github.com/prometheus/common/config"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
)

// Notifier implements a Notifier for Feishu bot notifications.
type Notifier struct {
	conf   *config.FeishuBotConfig
	tmpl   *template.Template
	logger log.Logger
	client *http.Client
}

type messageContent struct {
	Text string `json:"text"`
}

type message struct {
	Timestamp string         `json:"timestamp,omitempty"`
	Sign      string         `json:"sign,omitempty"`
	Content   messageContent `json:"content"`
	Type      string         `json:"msg_type"`
}

type response struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

// New returns a new Feishu bot notifier.
func New(c *config.FeishuBotConfig, t *template.Template, l log.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "feishubot", httpOpts...)
	if err != nil {
		return nil, err
	}

	return &Notifier{conf: c, tmpl: t, logger: l, client: client}, nil
}

// Notify implements the Notifier interface.
func (n *Notifier) Notify(ctx context.Context, as ...*types.Alert) (bool, error) {
	key, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		return false, err
	}

	level.Debug(n.logger).Log("incident", key)

	data := notify.GetTemplateData(ctx, n.tmpl, as, n.logger)
	tmpl := notify.TmplText(n.tmpl, data, &err)
	if err != nil {
		return false, err
	}

	// If the Feishu bot required keywords security authentication,
	// add the keywords to the content.
	var keywords string
	if n.conf.Keywords != nil && len(n.conf.Keywords) > 0 {
		keywords = "\n\n[Keywords] "
		for _, k := range n.conf.Keywords {
			keywords = fmt.Sprintf("%s%s, ", keywords, k)
		}

		keywords = strings.TrimSuffix(keywords, ", ")
	}

	content, truncated := notify.TruncateInBytes(tmpl(n.conf.Message), n.conf.MaxMessageSize-len(keywords))
	if truncated {
		level.Debug(n.logger).Log("msg", "message truncated due to exceeding maximum allowed length by feishu bot", "truncated_message", content)
	}

	content = fmt.Sprintf("%s%s", content, keywords)

	msg := &message{
		Type: "text",
		Content: messageContent{
			Text: content,
		},
	}

	// If the Feishu bot required signature security authentication,
	// add signature and timestamp to the message.
	if len(n.conf.Secret) > 0 {
		timestamp, sign, err := calcSign(string(n.conf.Secret))
		if err != nil {
			return false, err
		}

		msg.Timestamp = timestamp
		msg.Sign = sign
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return false, err
	}

	resp, err := notify.PostJSON(ctx, n.client, n.conf.WebhookURL.String(), &buf)
	if err != nil {
		return true, notify.RedactURL(err)
	}
	defer notify.Drain(resp)

	if resp.StatusCode != 200 {
		return true, fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	level.Debug(n.logger).Log("response", string(body), "incident", key)

	var feishuResp response
	if err := json.Unmarshal(body, &feishuResp); err != nil {
		return true, err
	}

	if feishuResp.Code == 0 {
		return false, nil
	}

	return false, errors.New(feishuResp.Message)
}

func calcSign(secret string) (string, string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	msg := fmt.Sprintf("%s\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(msg))
	_, err := h.Write(nil)
	if err != nil {
		return "", "", err
	}
	sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return timestamp, sign, nil
}
