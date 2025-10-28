# 功能说明

`csp-frame-ancestors` 插件用于动态管理响应头中的 Content-Security-Policy (CSP) frame-ancestors 指令。该插件根据请求的 Referer 头判断是否需要添加或修改 CSP 的 frame-ancestors 指令，从而控制哪些域名可以将当前页面嵌入到 iframe 中。

## 功能特性

- **Referer 匹配**：支持正则表达式匹配请求的 Referer 头
- **智能 CSP 处理**：
  - 当响应中不存在 CSP 头时，添加新的 CSP 头
  - 当 CSP 存在但没有 frame-ancestors 指令时，追加该指令
  - 当 frame-ancestors 为 `'none'` 时，删除 `'none'` 并替换为配置的值
  - 其他情况下，将配置的值追加到现有的 frame-ancestors 中

## 配置字段

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
| --- | --- | --- | --- | --- |
| referer_patterns | array of string | 必填 | - | Referer 匹配规则，支持正则表达式 |
| frame_ancestors | array of string | 必填 | - | 允许嵌入的域名列表 |

## 配置示例

### 基础配置

允许来自 example.com 和 trusted.com 域名的请求嵌入页面：

```yaml
referer_patterns:
  - "^https://example\\.com"
  - "^https://www\\.example\\.com"
frame_ancestors:
  - "https://example.com"
  - "https://www.example.com"
```

### 通配符域名配置

支持使用通配符匹配子域名：

```yaml
referer_patterns:
  - "^https://.*\\.example\\.com"
  - "^https://.*\\.trusted\\.com"
frame_ancestors:
  - "https://*.example.com"
  - "https://*.trusted.com"
  - "'self'"
```

### 多域名配置

配置多个信任域名：

```yaml
referer_patterns:
  - "^https://(www\\.)?example\\.com"
  - "^https://(www\\.)?partner\\.com"
  - "^https://app\\.company\\.com"
frame_ancestors:
  - "https://example.com"
  - "https://www.example.com"
  - "https://partner.com"
  - "https://app.company.com"
```

## 使用说明

### 场景 1：响应中没有 CSP 头

**原始响应：**
```
HTTP/1.1 200 OK
Content-Type: text/html
```

**插件处理后：**
```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Security-Policy: frame-ancestors https://example.com https://www.example.com
```

### 场景 2：CSP 存在但没有 frame-ancestors

**原始响应：**
```
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

**插件处理后：**
```
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors https://example.com https://www.example.com
```

### 场景 3：frame-ancestors 为 'none'

**原始响应：**
```
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
```

**插件处理后：**
```
HTTP/1.1 200 OK
Content-Security-Policy: frame-ancestors https://example.com https://www.example.com; default-src 'self'
```

### 场景 4：frame-ancestors 已存在

**原始响应：**
```
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; frame-ancestors https://old-site.com
```

**插件处理后：**
```
HTTP/1.1 200 OK
Content-Security-Policy: frame-ancestors https://old-site.com https://example.com https://www.example.com; default-src 'self'
```

## 注意事项

1. **正则表达式语法**：referer_patterns 使用 Go 的正则表达式语法，需要对特殊字符进行转义（如 `\.` 表示点号）
2. **性能考虑**：正则表达式匹配会在每个请求的请求头阶段执行，建议优化正则表达式以提高性能
3. **大小写敏感**：Referer 头的匹配是大小写敏感的
4. **协议匹配**：建议在正则表达式中明确指定协议（http/https）
5. **CSP 优先级**：frame-ancestors 指令会被放置在 CSP 字符串的最前面

## 常见问题

### Q: 如何匹配所有子域名？

使用正则表达式通配符：
```yaml
referer_patterns:
  - "^https://.*\\.example\\.com"
```

### Q: 是否支持 HTTP 和 HTTPS？

支持，可以在正则表达式中同时匹配：
```yaml
referer_patterns:
  - "^https?://example\\.com"
```

### Q: 如何允许页面被任意域名嵌入？

配置 `'*'` 作为 frame-ancestors 的值：
```yaml
frame_ancestors:
  - "*"
```

### Q: 插件是否会影响没有匹配到 Referer 的请求？

不会，只有当 Referer 匹配配置的正则表达式时，插件才会修改 CSP 头。

## 调试

插件会输出详细的日志信息，可以通过以下方式查看：

1. 检查 Higress 网关的日志
2. 使用浏览器开发者工具查看响应头中的 Content-Security-Policy
3. 启用插件的 Debug 日志级别以获取更详细的信息

## 版本历史

### v1.0.0
- 初始版本
- 支持基于 Referer 的 CSP frame-ancestors 动态管理
- 支持正则表达式匹配
- 智能处理各种 CSP 存在情况
