package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/tidwall/gjson"
	re "github.com/wasilibs/go-re2"
)

const (
	DefaultRejectedCode uint32 = 429
	DefaultRejectedMsg  string = "Too many requests"
)

type ClusterKeyRateLimitConfig struct {
	showLimitQuotaHeader bool            // 响应头中是否显示X-RateLimit-Limit和X-RateLimit-Remaining
	wihitlist            []WhitelistItem // 限流规则项
	rejectedCode         uint32          // 当请求超过阈值被拒绝时,返回的HTTP状态码
	rejectedMsg          string          // 当请求超过阈值被拒绝时,返回的响应体
	store                *store
}

type WhitelistItem struct {
	key    string
	regexp *re.Regexp
}

func parseClusterKeyRateLimitConfig(json gjson.Result, config *ClusterKeyRateLimitConfig) error {
	err := initWhitelist(json, config)
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
	if toekns.Exists() {
		config.store.tokens = uint64(toekns.Uint())
	} else {
		return errors.New("missing qps in config")
	}

	config.store = newStore(
		withTokens(toekns.Uint()),
		withInterval(time.Second),
	)
	return nil
}

func initWhitelist(json gjson.Result, config *ClusterKeyRateLimitConfig) error {
	whitelist := json.Get("whitelist")
	if len(whitelist.Array()) == 0 {
		return nil
	}
	var ruleItems []WhitelistItem
	for _, item := range whitelist.Array() {
		itemKey := item.String()
		var (
			regexp *re.Regexp
		)
		var err error
		regexp, err = re.Compile(itemKey)
		if err != nil {
			return fmt.Errorf("failed to compile regex for key '%s': %w", itemKey, err)
		}

		ruleItems = append(ruleItems, WhitelistItem{
			key:    itemKey,
			regexp: regexp,
		})
	}
	config.wihitlist = ruleItems
	return nil
}
