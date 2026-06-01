# Isolated Web Security Playbook

## When To Use

Use this playbook when the agent cannot directly browse or request the target, but the user can provide evidence or can run commands from an internal machine. The goal is to keep the assessment evidence-based without pretending that unreachable targets were actively tested.

## Evidence Intake Checklist

Ask for only the artifacts needed for the current question:

- Scope: target hostnames, paths, roles, environment, authorization, and forbidden actions.
- Browser evidence: HAR with content, screenshots, console errors, visible routes, and user flow notes.
- HTTP evidence: representative request/response pairs with method, URL, headers, body, status, response headers, and body sample.
- API evidence: OpenAPI, Postman/Burp export, route list, gateway config, or backend controller list.
- Frontend evidence: built JS/CSS/source maps, `src/` snippets, route config, API client modules, auth/session storage code.
- Auth/session evidence: sanitized `Set-Cookie`, cookie flags, token location, logout behavior, role matrix, object ID patterns.
- Server evidence: relevant error logs, access logs for test requests, reverse proxy/security header config.

Redaction rule: redact real tokens, cookies, passwords, PII, and production secrets. Keep header names, cookie names, claim names, status codes, and structural shapes intact.

## Collection Templates

### Browser HAR

1. Open DevTools Network.
2. Enable Preserve log and Disable cache.
3. Perform login and the target workflow with a test account.
4. Export HAR with content.
5. Redact credential values while preserving request paths, methods, parameter names, response headers, status codes, and response body structure.

### Browser Resource Snapshot

Use this only as a lightweight fallback. It does not include request bodies or all headers.

```javascript
copy(JSON.stringify(
  performance.getEntriesByType("resource").map((entry) => ({
    name: entry.name,
    initiatorType: entry.initiatorType,
    duration: Math.round(entry.duration),
    transferSize: entry.transferSize
  })),
  null,
  2
));
```

### Representative HTTP Transcript

```json
{
  "request": {
    "method": "POST",
    "url": "http://internal.example/api/example",
    "headers": {
      "Content-Type": "application/json",
      "Cookie": "<redacted test cookie>"
    },
    "body": {"field": "baseline"}
  },
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "application/json",
      "Set-Cookie": "sid=<redacted>; HttpOnly; SameSite=Lax"
    },
    "body_sample": {"ok": true}
  }
}
```

### Internal Curl Runner

Have the internal runner execute baseline first, then the probe. Save headers and body separately.

```powershell
curl.exe -k -i -sS -X GET "http://internal.example/path?field=baseline" `
  -H "Cookie: <redacted-or-test-cookie>" `
  -o body-baseline.txt `
  -D headers-baseline.txt
```

For JSON POST:

```powershell
curl.exe -k -i -sS -X POST "http://internal.example/api/search" `
  -H "Content-Type: application/json" `
  -H "Cookie: <redacted-or-test-cookie>" `
  --data "{\"keyword\":\"baseline\"}" `
  -o body-baseline.txt `
  -D headers-baseline.txt
```

### Static Frontend Discovery

Run these from the frontend source or built asset directory:

```powershell
rg -n "fetch\(|axios|XMLHttpRequest|/api/|Authorization|Bearer|localStorage|sessionStorage|postMessage|innerHTML|outerHTML|document\.write|location\.href|window\.open|sourceMappingURL" .
```

Return only relevant matches and surrounding code. Redact secrets.

## Internal Probe Packet Format

When the agent cannot execute the probe, produce a packet the internal runner can follow:

```text
Probe ID: SQLI-001
Goal: Check whether the `keyword` field changes database behavior.
Baseline request: POST /api/search {"keyword":"nurse"}
Probe request: POST /api/search {"keyword":"nurse'"}
Compare: status, response length, error text, server log error, timing.
Evidence of risk: SQL syntax error, database driver message, or consistent boolean/timing difference.
Stop condition: stop after one error signal or after baseline/probe comparison is inconclusive.
Safety: do not extract table names or data.
```

Use the same pattern for XSS, access control, CORS, cookie flags, redirects, upload/download, and IDOR checks.

## Offline Analysis Heuristics

- Security headers: assess from response headers alone. Missing `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, strict cache headers for sensitive pages, and HSTS/TLS issues are reportable with limitations.
- Cookie/session: assess `HttpOnly`, `Secure`, `SameSite`, path/domain scope, duplicate session cookies, token storage location, and logout invalidation evidence.
- CORS: report wildcard origin with credentials, origin reflection, and missing `Vary: Origin` when shown in headers.
- Access control: require role-specific evidence. If only one role is supplied, list IDOR/forced browsing as unverified and request role-paired transcripts.
- Injection: require request fields and baseline/probe comparison. Do not mark confirmed from payload plans alone.
- XSS: confirm only when supplied response/DOM evidence shows unsafe reflection or execution context. Otherwise report as candidate sink/input needing browser validation.
- Sensitive exposure: source maps, stack traces, internal paths, debug endpoints, verbose error JSON, tokens in frontend bundles, and PII in responses can be confirmed from artifacts.

## Report Template

Start every final report with a concrete name. After the report or internal
execution plan is complete, call `generate_markdown_report` with the same report
name and the full Markdown content, then include the returned path in the final
response:

```text
报告名称：<system or workflow>内外网隔离安全检测报告

## 网络限制
- 当前 agent 是否可直连目标：
- 采用模式：artifact-only / guided internal execution / direct internal browser
- 未覆盖原因：

## 样本覆盖
- 已分析的页面、接口、角色、请求样本、静态文件、日志：
- 缺失样本：

## 攻击类型
- 已验证：
- 基于证据的高概率风险：
- 未验证但建议内部执行：

## 发现与证据
- 风险等级：
- 影响位置：
- 证据：
- 复现或内部执行步骤：

## 修复建议
- 代码/配置修复：
- 验证方式：

## 内部复测清单
- 按优先级列出下一轮内部执行命令或请求。
```

Do not blur confirmed and unverified findings. If the only output is a plan, call it an internal execution plan, not a completed vulnerability scan.
