package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	re "github.com/wasilibs/go-re2"
)

const (
	DefaultRejectedCode uint32 = 403
	DefaultRejectedMsg  string = "Too many ip count requests"

	Second           int64 = 1
	SecondsPerMinute       = 60 * Second
	SecondsPerHour         = 60 * SecondsPerMinute
	SecondsPerDay          = 24 * SecondsPerHour
)

var timeWindows = map[string]int64{
	"count_per_second": Second,
	"count_per_minute": SecondsPerMinute,
	"count_per_hour":   SecondsPerHour,
	"count_per_day":    SecondsPerDay,
}

type ClusterIPCountLimitConfig struct {
	ruleName     string            // 限流规则名称
	configItems  []LimitConfigItem // 限流规则项
	rejectedCode uint32            // 当请求超过阈值被拒绝时,返回的HTTP状态码
	rejectedMsg  string            // 当请求超过阈值被拒绝时,返回的响应体
	redisClient  wrapper.RedisClient
}

type LimitConfigItem struct {
	key              string              // 限流key
	regexp           *re.Regexp          // 正则表达式
	whitelist        map[string]struct{} // 白名单
	whitelistRegexps []*re.Regexp        // 白名单正则表达式
	ipWhitelist      []*net.IPNet        // ip subnet whitelist
	count            int64               // 指定时间窗口内的总请求数量阈值
	timeWindow       int64               // 时间窗口大小
}

func initRedisClusterClient(json gjson.Result, config *ClusterIPCountLimitConfig) error {
	redisConfig := json.Get("redis")
	if !redisConfig.Exists() {
		return errors.New("missing redis in config")
	}
	serviceName := redisConfig.Get("service_name").String()
	if serviceName == "" {
		return errors.New("redis service name must not be empty")
	}
	servicePort := int(redisConfig.Get("service_port").Int())
	if servicePort == 0 {
		if strings.HasSuffix(serviceName, ".static") {
			// use default logic port which is 80 for static service
			servicePort = 80
		} else {
			servicePort = 6379
		}
	}
	username := redisConfig.Get("username").String()
	password := redisConfig.Get("password").String()
	timeout := int(redisConfig.Get("timeout").Int())
	if timeout == 0 {
		timeout = 1000
	}
	config.redisClient = wrapper.NewRedisClusterClient(wrapper.FQDNCluster{
		FQDN: serviceName,
		Port: int64(servicePort),
	})
	database := int(redisConfig.Get("database").Int())
	return config.redisClient.Init(username, password, int64(timeout), wrapper.WithDataBase(database))
}

func parseClusterKeyRateLimitConfig(json gjson.Result, config *ClusterIPCountLimitConfig) error {
	ruleName := json.Get("rule_name")
	if !ruleName.Exists() {
		return errors.New("missing rule_name in config")
	}
	config.ruleName = ruleName.String()

	// 初始化ruleItems
	configItems, err := initConfigItems(json)
	if err != nil {
		return err
	}
	config.configItems = configItems

	rejectedCode := json.Get("rejected_code")
	if rejectedCode.Exists() {
		config.rejectedCode = uint32(rejectedCode.Uint())
	} else {
		config.rejectedCode = DefaultRejectedCode
	}
	rejectedMsg := json.Get("rejected_msg")
	if rejectedMsg.Exists() {
		config.rejectedMsg = rejectedMsg.String()
	} else {
		config.rejectedMsg = DefaultRejectedMsg
	}
	return nil
}

func initConfigItems(json gjson.Result) ([]LimitConfigItem, error) {
	limitKeys := json.Get("config")
	if !limitKeys.Exists() {
		return nil, errors.New("missing config in config")
	}
	if len(limitKeys.Array()) == 0 {
		return nil, errors.New("config cannot be empty")
	}
	var configItems []LimitConfigItem
	for _, item := range limitKeys.Array() {
		key := item.Get("key")
		if !key.Exists() || key.String() == "" {
			return nil, errors.New("config_items key is required")
		}

		var (
			itemKey = key.String()
			regexp  *re.Regexp
		)
		if strings.HasPrefix(itemKey, "regexp:") {
			regexpStr := itemKey[len("regexp:"):]
			var err error
			regexp, err = re.Compile(regexpStr)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex for key '%s': %w", itemKey, err)
			}
		}

		var (
			whitelist        = make(map[string]struct{})
			whitelistRegexps []*re.Regexp
		)

		whitelistStr := item.Get("whitelist")
		if whitelistStr.Exists() {
			for _, whitelistItem := range whitelistStr.Array() {
				if strings.HasPrefix(whitelistItem.String(), "regexp:") {
					whitelistRegexp, err := re.Compile(whitelistItem.String()[len("regexp:"):])
					if err != nil {
						return nil, fmt.Errorf("failed to compile regex for whitelist item '%s': %w", whitelistItem.String(), err)
					}
					whitelistRegexps = append(whitelistRegexps, whitelistRegexp)
				} else {
					whitelist[whitelistItem.String()] = struct{}{}
				}
			}
		}

		var ipWhitelist []*net.IPNet
		ipWhitelistStr := item.Get("ip_whitelist")
		if ipWhitelistStr.Exists() {
			for _, ipWhitelistItem := range ipWhitelistStr.Array() {
				ipWhitelistItem := ipWhitelistItem.String()
				ipNet, err := ParseSubnet(ipWhitelistItem)
				if err != nil {
					return nil, fmt.Errorf("failed to parse ip whitelist item '%s': %w", ipWhitelistItem, err)
				}
				ipWhitelist = append(ipWhitelist, ipNet)
			}
		}

		if configItem, err := createConfigItemFromRate(item, itemKey, regexp, whitelist, whitelistRegexps, ipWhitelist); err != nil {
			return nil, err
		} else if configItem != nil {
			configItems = append(configItems, *configItem)
		}
	}
	return configItems, nil
}

func createConfigItemFromRate(item gjson.Result, key string, regexp *re.Regexp, whitelist map[string]struct{}, whitelistRegexps []*re.Regexp, ipWhitelist []*net.IPNet) (*LimitConfigItem, error) {
	for timeWindowKey, duration := range timeWindows {
		q := item.Get(timeWindowKey)
		if q.Exists() && q.Int() > 0 {
			return &LimitConfigItem{
				key:              key,
				regexp:           regexp,
				whitelist:        whitelist,
				whitelistRegexps: whitelistRegexps,
				ipWhitelist:      ipWhitelist,
				count:            q.Int(),
				timeWindow:       duration,
			}, nil
		}
	}
	return nil, errors.New("one of 'query_per_second', 'query_per_minute', 'query_per_hour', or 'query_per_day' must be set for key: " + key)
}
