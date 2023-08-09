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

package dingtalkrobot

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
	"net/url"
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

// Notifier implements a Notifier for DingTalk robot notifications.
type Notifier struct {
	conf   *config.DingTalkRobotConfig
	tmpl   *template.Template
	logger log.Logger
	client *http.Client
}

type messageContent struct {
	Content string `json:"content"`
}

type message struct {
	Text messageContent `json:"text"`
	Type string         `json:"msgtype"`
}

type response struct {
	Code    int    `json:"errcode"`
	Message string `json:"errmsg"`
}

// New returns a new DingTalk robot notifier.
func New(c *config.DingTalkRobotConfig, t *template.Template, l log.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "dingtalkrobot", httpOpts...)
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

	// If the DingTalk robot required keywords security authentication,
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
		level.Debug(n.logger).Log("msg", "message truncated due to exceeding maximum allowed length by dingtalk robot", "truncated_message", content)
	}

	content = fmt.Sprintf("%s%s", content, keywords)

	msg := &message{
		Type: "text",
		Text: messageContent{
			Content: content,
		},
	}

	// If the DingTalk robot required signature security authentication,
	// add signature and timestamp to the url.
	if len(n.conf.Secret) > 0 {
		timestamp, sign, err := calcSign(string(n.conf.Secret))
		if err != nil {
			return false, err
		}

		q := n.conf.WebhookURL.Query()
		q.Set("timestamp", timestamp)
		q.Set("sign", sign)
		n.conf.WebhookURL.RawQuery = q.Encode()
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

	var dingtalkResp response
	if err := json.Unmarshal(body, &dingtalkResp); err != nil {
		return true, err
	}

	if dingtalkResp.Code == 0 {
		return false, nil
	}

	return false, errors.New(dingtalkResp.Message)
}

func calcSign(secret string) (string, string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix()*1000)
	msg := fmt.Sprintf("%s\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(msg))
	if err != nil {
		return "", "", err
	}
	sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return timestamp, url.QueryEscape(sign), nil
}
