package main

import (
	"fmt"
	"strings"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/log"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/resp"
)

const (
	ClusterIPCountLimitFormat = "higress-cluster-ip-count-limit:%s:%s" // 规则名:key:域名
	CheckIPLimitScript        = `
	local key = KEYS[1]
	local ip = ARGV[1]
	local maxCount = tonumber(ARGV[2])
	local window = tonumber(ARGV[3])

	local count = redis.call("SCARD", key)
	if count < maxCount then
		redis.call("SADD", key, ip)
		if count == 0 then
			redis.call("EXPIRE", key, window)
		end
		return 1
	end

	return redis.call("SISMEMBER", key, ip)
	`
)

func main() {
	wrapper.SetCtx(
		"cluster-ip-count-limit",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *ClusterIPCountLimitConfig, log log.Log) error {
	if err := initRedisClusterClient(json, config); err != nil {
		return err
	}
	return parseClusterKeyRateLimitConfig(json, config)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config ClusterIPCountLimitConfig, log log.Log) types.Action {
	// 1. 获取请求域名
	host := ctx.Host()

	// 2. 匹配域名规则
	var matchedItem LimitConfigItem
	for _, item := range config.ruleItems {
		if item.regexp != nil && item.regexp.MatchString(host) ||
			item.key == host {
			matchedItem = item
			break
		}
	}
	if matchedItem.key == "" {
		log.Debugf("no matching rule for host: %s", host)
		return types.ActionContinue
	}

	// 3. 获取真实客户端IP
	realIP, err := getRealIP()
	if err != nil {
		log.Warnf("failed to get real IP: %v", err)
		return types.ActionContinue
	}

	if len(matchedItem.ipWhitelist) > 0 && IsIPInSubnets(realIP, matchedItem.ipWhitelist) {
		log.Debugf("ip %s is in whitelist", realIP)
		return types.ActionContinue
	}

	// 4. 构建Redis参数
	redisKey := fmt.Sprintf(ClusterIPCountLimitFormat, config.ruleName, host)
	keys := []interface{}{redisKey}
	args := []interface{}{realIP, matchedItem.count, matchedItem.timeWindow}

	// 5. 执行限流检查
	err = config.redisClient.Eval(CheckIPLimitScript, 1, keys, args, func(response resp.Value) {
		if err := response.Error(); err != nil {
			log.Errorf("redis call failed: %v", err)
			proxywasm.ResumeHttpRequest()
			return
		}
		if response.Integer() == 1 {
			proxywasm.ResumeHttpRequest()
		} else {
			rejected(config, log)
		}
	})
	if err != nil {
		log.Errorf("redis call failed: %v", err)
		return types.ActionContinue
	}
	return types.ActionPause
}

// 获取真实客户端IP（支持代理场景）
func getRealIP() (string, error) {
	// 优先从X-Forwarded-For获取
	if xff, err := proxywasm.GetHttpRequestHeader("X-Forwarded-For"); err == nil {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0]), nil
		}
	}

	// 直接从连接获取源地址
	bs, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil {
		return "", fmt.Errorf("get source address failed: %w", err)
	}

	return parseIP(string(bs)), nil
}

// 拒绝请求处理
func rejected(config ClusterIPCountLimitConfig, log log.Log) {
	_ = proxywasm.SendHttpResponse(
		config.rejectedCode,
		nil,
		[]byte(config.rejectedMsg),
		-1,
	)
	log.Infof("Request rejected by IP count limit")
}
