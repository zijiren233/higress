package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	re "github.com/wasilibs/go-re2"
)

const (
	DefaultRejectedCode uint32 = 429
	DefaultRejectedMsg  string = "Too many requests"
)

type ClusterKeyRateLimitConfig struct {
	showLimitQuotaHeader bool               // 响应头中是否显示X-RateLimit-Limit和X-RateLimit-Remaining
	whitelistReg         []WhitelistRegItem // 限流规则项
	rawWhitlistMap       map[string]struct{}
	rejectedCode         uint32 // 当请求超过阈值被拒绝时,返回的HTTP状态码
	rejectedMsg          string // 当请求超过阈值被拒绝时,返回的响应体
	store                *store
}

type WhitelistRegItem struct {
	key    string
	regexp *re.Regexp
}

func parseClusterKeyRateLimitConfig(json gjson.Result, config *ClusterKeyRateLimitConfig, log wrapper.Log) error {
	err := initWhitelist(json, config, log)
	if err != nil {
		return err
	}

	showLimitQuotaHeader := json.Get("show_limit_quota_header")
	if showLimitQuotaHeader.Exists() {
		config.showLimitQuotaHeader = showLimitQuotaHeader.Bool()
	}

	rejectedCode := json.Get("rejected_code")
	if rejectedCode.Exists() {
		config.rejectedCode = uint32(rejectedCode.Uint())
	} else {
		config.rejectedCode = DefaultRejectedCode
	}
	rejectedMsg := json.Get("rejected_msg")
	if rejectedCode.Exists() {
		config.rejectedMsg = rejectedMsg.String()
	} else {
		config.rejectedMsg = DefaultRejectedMsg
	}

	toekns := json.Get("qps")
	if !toekns.Exists() || toekns.Uint() == 0 {
		return errors.New("qps must be greater than 0")
	}

	config.store = newStore(
		withTokens(toekns.Uint()),
		withInterval(time.Second),
	)
	return nil
}

func initWhitelist(json gjson.Result, config *ClusterKeyRateLimitConfig, log wrapper.Log) error {
	whitelist := json.Get("whitelist")
	if !whitelist.Exists() && len(whitelist.Array()) == 0 {
		log.Warn("no whitelist rule found, all requests will be rejected")
		return nil
	}
	config.whitelistReg = make([]WhitelistRegItem, 0)
	config.rawWhitlistMap = make(map[string]struct{})
	for _, item := range whitelist.Array() {
		itemKey := item.String()
		if strings.HasPrefix(itemKey, "regexp:") {
			regexpStr := itemKey[len("regexp:"):]
			regexp, err := re.Compile(regexpStr)
			if err != nil {
				return fmt.Errorf("failed to compile regex for key '%s': %w", itemKey, err)
			}

			config.whitelistReg = append(config.whitelistReg, WhitelistRegItem{
				key:    itemKey,
				regexp: regexp,
			})
			continue
		}
		config.rawWhitlistMap[itemKey] = struct{}{}
	}
	return nil
}
