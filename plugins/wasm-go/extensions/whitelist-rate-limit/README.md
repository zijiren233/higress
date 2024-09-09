---
title: 基于 Host 白名单单机限流
keywords: [higress, rate-limit]
description: 基于 Host 白名单单机限流插件配置参考
---

## 功能说明

## 配置说明

| 配置项                  | 类型            | 必填 | 默认值            | 说明                                                                                                       |
| ----------------------- | --------------- | ---- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| whitelist               | array of string | 是   | -                 | 限流白名单规则项，是一个regexp:开头代表是正则表达式，                                                      |
| qps                     | int             | 是   | -                 | 限流qps                                                                                                    |
| show_limit_quota_header | bool            | 否   | false             | 响应头中是否显示 `X-RateLimit-Limit`（限制的总请求数）和 `X-RateLimit-Remaining`（剩余还可以发送的请求数） |
| rejected_code           | int             | 否   | 429               | 请求被限流时，返回的 HTTP 状态码                                                                           |
| rejected_msg            | string          | 否   | Too many requests | 请求被限流时，返回的响应体                                                                                 |

## 配置示例

### 识别请求参数 apikey，进行区别限流

```yaml
qps: 10
whitelist:
- ^applaunchpad\.
- ^costcenter\.
show_limit_quota_header: true
```
