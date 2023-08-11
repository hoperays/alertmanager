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

package wecomrobot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	commoncfg "github.com/prometheus/common/config"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
)

// Notifier implements a Notifier for WeCom robot notifications.
type Notifier struct {
	conf   *config.WeComRobotConfig
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

// New returns a new WeCom robot notifier.
func New(c *config.WeComRobotConfig, t *template.Template, l log.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "wecomrobot", httpOpts...)
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

	content, truncated := notify.TruncateInBytes(tmpl(n.conf.Message), n.conf.MaxMessageSize)
	if truncated {
		level.Debug(n.logger).Log("msg", "message truncated due to exceeding maximum allowed length by wecom robot", "truncated_message", content)
	}

	msg := message{
		Type: "text",
		Text: messageContent{
			Content: content,
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return false, err
	}

	resp, err := notify.PostJSON(ctx, n.client, n.conf.WebhookURL.String(), &buf)
	if err != nil {
		return true, err
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

	var wecomResp response
	if err := json.Unmarshal(body, &wecomResp); err != nil {
		return true, err
	}

	// https://developer.work.weixin.qq.com/document/path/90313
	if wecomResp.Code == 0 {
		return false, nil
	}

	return false, errors.New(wecomResp.Message)
}
