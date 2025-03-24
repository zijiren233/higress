---
title: IP-Based Cluster Count Limiting
keywords: [higress, ip-count-limit]
description: Configuration reference for the IP-Based Cluster Count Limiting plugin
---

## Function Description

The `cluster-ip-count-limit` plugin implements cluster IP count limiting based on Redis, suitable for scenarios that require limiting the total number of different IP addresses accessing across multiple Higress Gateway instances within the same time period.
This plugin can limit the number of different IP addresses allowed within a specified time window, and new IP addresses exceeding the limit will be denied access.

## Execution Attributes

Plugin Execution Phase: `default phase`
Plugin Execution Priority: `20`

## Configuration Description

| Configuration Item        | Type          | Required | Default Value | Description                                                                          |
| ------------------------- | ------------- | -------- | ------------- | ------------------------------------------------------------------------------------ |
| rule_name                 | string        | Yes      | -             | The name of the rate limiting rule. The Redis key is constructed using rule name + domain name |
| rule_items              | array of object | Yes    | -             | Rate limiting rule items. The first matching `rule_items` based on the order under `rule_items` will trigger the rate limiting, and subsequent rules will be ignored |
| rejected_code             | int           | No       | 403           | HTTP status code returned when a request is rate limited                             |
| rejected_msg              | string        | No       | Too many ip count requests | Response body returned when a request is rate limited                   |
| redis                     | object        | Yes      | -             | Redis related configuration                                                          |

Description of configuration fields for each item in `rule_items`.

| Configuration Item        | Type            | Required                | Default Value | Description                                                                                                                                                       |
| ------------------------- | --------------- | ----------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| key                       | string          | Yes                     | -             | Matched domain name, supports regular expression configuration (starting with regexp: followed by a regular expression), e.g., `regexp:^api.*\.example\.com$` (matches example.com subdomains starting with api) |
| whitelist                 | array of string | No                      | -             | Domain name whitelist, supports regular expression configuration (starting with regexp: followed by a regular expression)                                          |
| ip_whitelist              | array of string | No                      | -             | IP whitelist, supports configuring IP addresses or IP segments, e.g., `192.168.1.1` or `192.168.1.0/24`                                                           |
| count_per_second          | int             | No, one of `count_per_*` is optional | - | Number of different IP addresses allowed per second                                                                                                              |
| count_per_minute          | int             | No, one of `count_per_*` is optional | - | Number of different IP addresses allowed per minute                                                                                                              |
| count_per_hour            | int             | No, one of `count_per_*` is optional | - | Number of different IP addresses allowed per hour                                                                                                                |
| count_per_day             | int             | No, one of `count_per_*` is optional | - | Number of different IP addresses allowed per day                                                                                                                 |

Description of configuration fields for each item in `redis`.

| Configuration Item | Type   | Required | Default Value                          | Description                                                                                                     |
| ------------------ | ------ | -------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| service_name       | string | Required | -                                      | Full FQDN name of the Redis service, including service type, e.g., my-redis.dns, redis.my-ns.svc.cluster.local  |
| service_port       | int    | No       | 80 for static services; otherwise 6379 | Service port for the Redis service                                                                              |
| username           | string | No       | -                                      | Redis username                                                                                                  |
| password           | string | No       | -                                      | Redis password                                                                                                  |
| timeout            | int    | No       | 1000                                   | Redis connection timeout in milliseconds                                                                        |
| database           | int    | No       | 0                                      | The database ID used, for example, configured as 1, corresponds to `SELECT 1`                                   |

## Configuration Example

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
