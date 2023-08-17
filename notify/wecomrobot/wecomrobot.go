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
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	commoncfg "github.com/prometheus/common/config"
)

// Notifier implements a Notifier for generic wecomrobot.
type Notifier struct {
	conf   *config.WeComRobotConfig
	tmpl   *template.Template
	logger log.Logger
	client *http.Client
}

type weComRobotResponse struct {
	Code  int    `json:"errcode"`
	Error string `json:"errmsg"`
}

// New returns a new Wechat notifier.
func New(c *config.WeComRobotConfig, t *template.Template, l log.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "wecomrobot", httpOpts...)
	if err != nil {
		return nil, err
	}

	return &Notifier{conf: c, tmpl: t, logger: l, client: client}, nil
}

type Mark struct {
	Content string `json:"content"`
}

type WeComRobotMessage struct {
	Msgtype string `json:"msgtype"`
	Text    Mark   `json:"text"`
}

// Notify implements the Notifier interface.
func (n *Notifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {
	var (
		tmplErr error
		data    = notify.GetTemplateData(ctx, n.tmpl, alerts, n.logger)
		tmpl    = notify.TmplText(n.tmpl, data, &tmplErr)
	)

	message := tmpl(n.conf.Message)
	if tmplErr != nil {
		return false, fmt.Errorf("templating error: %s", tmplErr)
	}

	content, truncated := notify.TruncateInBytes(message, n.conf.MaxMessageSize)
	if truncated {
		level.Debug(n.logger).Log("msg", "message truncated due to exceeding maximum allowed length by wecom robot", "truncated_message", content)
	}

	msg := WeComRobotMessage{
		Msgtype: "text",
		Text:    Mark{Content: content},
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	level.Debug(n.logger).Log("response", string(body))

	var wecomrobotResp weComRobotResponse
	if err := json.Unmarshal(body, &wecomrobotResp); err != nil {
		return true, err
	}

	// https://developer.work.weixin.qq.com/document/path/90313
	if wecomrobotResp.Code == 0 {
		return false, nil
	}

	return false, errors.New(wecomrobotResp.Error)
}
