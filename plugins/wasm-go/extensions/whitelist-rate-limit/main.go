// Copyright (c) 2024 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strconv"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

func main() {
	wrapper.SetCtx(
		"whitelist-rate-limit",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
	)
}

const (
	LimitContextKey string = "LimitContext" // 限流上下文信息

	RateLimitLimitHeader     string = "X-RateLimit-Limit"     // 限制的总请求数
	RateLimitRemainingHeader string = "X-RateLimit-Remaining" // 剩余还可以发送的请求数
	RateLimitResetHeader     string = "X-RateLimit-Reset"     // 限流重置时间（触发限流时返回）
)

type LimitContext struct {
	count     uint64
	remaining uint64
	reset     uint64
}

func parseConfig(json gjson.Result, config *ClusterKeyRateLimitConfig, log wrapper.Log) error {
	return parseClusterKeyRateLimitConfig(json, config)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config ClusterKeyRateLimitConfig, log wrapper.Log) types.Action {
	// 判断是否命中限流规则
	val, ok := checkRequestAgainstLimitRule(ctx, config.wihitlist, log)
	if ok {
		return types.ActionContinue
	}

	// 执行限流逻辑
	count, remating, reset, ok := config.store.Take(val)
	context := LimitContext{
		count:     count,
		remaining: remating,
		reset:     reset,
	}
	if !ok {
		// 触发限流
		rejected(config, context)
	} else {
		ctx.SetContext(LimitContextKey, context)
		proxywasm.ResumeHttpRequest()
	}
	return types.ActionPause
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config ClusterKeyRateLimitConfig, log wrapper.Log) types.Action {
	limitContext, ok := ctx.GetContext(LimitContextKey).(LimitContext)
	if !ok {
		return types.ActionContinue
	}
	if config.showLimitQuotaHeader {
		_ = proxywasm.ReplaceHttpResponseHeader(RateLimitLimitHeader, strconv.FormatUint(limitContext.count, 10))
		_ = proxywasm.ReplaceHttpResponseHeader(RateLimitRemainingHeader, strconv.FormatUint(limitContext.remaining, 10))
	}
	return types.ActionContinue
}

func checkRequestAgainstLimitRule(ctx wrapper.HttpContext, whitelist []WhitelistItem, log wrapper.Log) (string, bool) {
	val, err := proxywasm.GetHttpRequestHeader("Host")
	if err != nil {
		return "", false
	}
	for _, rule := range whitelist {
		if rule.regexp.MatchString(val) {
			return val, true
		}
	}
	return val, false
}

func rejected(config ClusterKeyRateLimitConfig, context LimitContext) {
	headers := make(map[string][]string)
	headers[RateLimitResetHeader] = []string{strconv.FormatUint(context.reset, 10)}
	if config.showLimitQuotaHeader {
		headers[RateLimitLimitHeader] = []string{strconv.FormatUint(context.count, 10)}
		headers[RateLimitRemainingHeader] = []string{strconv.Itoa(0)}
	}
	_ = proxywasm.SendHttpResponseWithDetail(
		config.rejectedCode, "cluster-key-rate-limit.rejected", reconvertHeaders(headers), []byte(config.rejectedMsg), -1)
}
