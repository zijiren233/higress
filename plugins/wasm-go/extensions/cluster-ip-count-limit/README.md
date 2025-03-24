---
title: 基于 IP 集群计数限流
keywords: [higress, ip-count-limit]
description: 基于 IP 集群计数限流插件配置参考
---

## 功能说明

`cluster-ip-count-limit` 插件基于 Redis 实现集群 IP 计数限流，适用于需要跨多个 Higress Gateway 实例限制同一时间段内不同 IP 访问总数的场景。
该插件可以限制在指定时间窗口内允许的不同 IP 地址数量，超过限制的新 IP 地址将被拒绝访问。

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`20`

## 配置说明

| 配置项                  | 类型   | 必填 | 默认值 | 说明                                                                          |
| ----------------------- | ------ | ---- | ------ |-----------------------------------------------------------------------------|
| rule_name               | string | 是 | - | 限流规则名称，根据限流规则名称 + 域名来拼装 redis key             |
| rule_items | array of object | 是   | -                 | 限流规则项，按照 rule_items 下的排列顺序，匹配第一个 config_item 后命中限流规则，后续规则将被忽略                 |
| rejected_code           | int | 否 | 403 | 请求被限流时，返回的 HTTP 状态码                                                         |
| rejected_msg            | string | 否 | Too many ip count requests | 请求被限流时，返回的响应体                                                               |
| redis                   | object          | 是                                                           | -                 | redis 相关配置                                                                  |

`rule_items` 中每一项的配置字段说明。

| 配置项                | 类型            | 必填                   | 默认值 | 说明                                                                                                                                                       |
| --------------------- | --------------- |----------------------| ------ |----------------------------------------------------------------------------------------------------------------------------------------------------------|
| key                   | string          | 是                    | -      | 匹配的域名，支持配置正则表达式（以regexp:开头后面跟正则表达式），正则表达式示例：`regexp:^api.*\.example\.com$`（匹配以api开头的example.com子域名）                                                                                                                                   |
| whitelist             | array of string | 否                    | -      | 域名白名单，支持配置正则表达式（以regexp:开头后面跟正则表达式）                                                                                                                                     |
| ip_whitelist          | array of string | 否                    | -      | IP 白名单，支持配置 IP 地址或 IP 段，例如：`192.168.1.1` 或 `192.168.1.0/24`                                                                                                                               |
| count_per_second      | int             | 否，`count_per_*` 中选填一项 | -      | 每秒允许的不同 IP 地址数量                                                                                                                               |
| count_per_minute      | int             | 否，`count_per_*` 中选填一项 | -      | 每分钟允许的不同 IP 地址数量                                                                                                                               |
| count_per_hour        | int             | 否，`count_per_*` 中选填一项 | -      | 每小时允许的不同 IP 地址数量                                                                                                                               |
| count_per_day         | int             | 否，`count_per_*` 中选填一项 | -      | 每天允许的不同 IP 地址数量                                                                                                                               |

`redis` 中每一项的配置字段说明。

| 配置项       | 类型   | 必填 | 默认值                                                     | 说明                                                                                         |
| ------------ | ------ | ---- | ---------------------------------------------------------- | ---------------------------------------------------------------------------                  |
| service_name | string | 必填 | -                                                          | redis 服务名称，带服务类型的完整 FQDN 名称，例如 my-redis.dns、redis.my-ns.svc.cluster.local |
| service_port | int    | 否   | 服务类型为固定地址（static service）默认值为80，其他为6379 | 输入redis服务的服务端口                                                                      |
| username     | string | 否   | -                                                          | redis 用户名                                                                                 |
| password     | string | 否   | -                                                          | redis 密码                                                                                   |
| timeout      | int    | 否   | 1000                                                       | redis 连接超时时间，单位毫秒                                                                 |
| database     | int    | 否   | 0                                                          | 使用的数据库id，例如配置为1，对应`SELECT 1`                                                  |

## 配置示例

```yaml
rule_name: ip-count-limit
rule_items:
  - key: "regexp:^api.*\.example\.com$"
    whitelist:
      - "api1.example.com"
      - "api2.example.com"
    ip_whitelist:
      - "192.168.1.1"
      - "192.168.1.0/24"
    count_per_minute: 10
redis:
  service_name: redis.static
```
