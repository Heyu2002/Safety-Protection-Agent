---
name: isolated-web-security-assessment
description: Guide authorized web security assessment when the agent or host cannot directly access the target because internal and external networks are disconnected, isolated, air-gapped, intranet-only, VPN-only, jump-host-only, no-route, 内外网不互通, 内网隔离, 网络隔离, 无法直连, 无法访问, or when the user provides HAR, curl, HTTP transcripts, Postman/Burp exports, source bundles, logs, or screenshots instead of live access. Use for offline evidence-driven vulnerability discovery, internal-runner probe planning, report generation, and remediation guidance.
---

# Isolated Web Security Assessment

## Operating Mode

- Treat network isolation as a normal constraint, not as a reason to stop. Switch from live probing to evidence-driven analysis and guided internal execution.
- Do not call live HTTP/browser tools against a target unless the current host or MCP browser is actually inside the reachable network. If reachability is unclear, ask for one concrete connectivity fact.
- Ask for sanitized artifacts instead of production secrets. Prefer HAR/curl/request-response samples with tokens redacted or short-lived test credentials created for the assessment.
- Separate findings into `confirmed from supplied evidence`, `validated by internal execution`, and `hypotheses needing internal execution`.
- Keep probes low impact. Do not request destructive actions, data extraction, persistence, stealth, or availability disruption.

## Workflow

1. Confirm topology and scope: target system, authorization, why the agent cannot reach it, who can run commands inside the internal network, account roles, and allowed test intensity.
2. Pick one mode:
   - Artifact-only: the user can provide HAR, request/response transcripts, static files, screenshots, logs, or API specs.
   - Guided internal execution: the user or CI runner can execute generated curl/browser/tool steps inside the internal network and return outputs.
   - Direct internal browser: MCP/Chrome is already connected to VPN/internal network; use the normal web workflow, but record the network assumption.
3. Request the smallest useful evidence bundle: representative URLs/routes, HAR with content, sanitized headers/cookies, request bodies, response headers/bodies, role matrix, API docs, JS/static bundles, screenshots, and relevant server errors/log snippets.
4. Map the attack surface offline: endpoints, methods, parameters, content types, auth/session artifacts, cookies, redirects, CORS, uploads/downloads, object IDs, role-sensitive operations, and client-side API discovery from JS.
5. Produce an internal probe packet when evidence is insufficient: exact low-impact requests, baseline/probe comparisons, fields to mutate, headers to preserve, expected observations, and stop conditions.
6. Analyze returned internal-runner results. Iterate only on evidence gaps that materially affect risk or exploitability.
7. Report in Chinese. Start with `报告名称：<target-specific report name>`, then include network limitation, evidence received, sample coverage, attack types, confirmed/probable/not-tested findings, risk level, fixes, and internal retest steps.
8. After the formal report or internal execution plan is complete, call `generate_markdown_report` with `report_name` and the full `report_markdown`, then include the returned path in the final answer. Do not call it while still asking for missing artifacts.

## Tool Guidance

- Use browser/MCP tools only when they can reach the internal target. If they fail because of network isolation, stop retrying and ask for artifacts or internal-runner output.
- Use built-in HTTP scan tools only for targets reachable from the current process or a local replay endpoint. Otherwise, generate ready-to-run internal probe instructions instead of calling the tool.
- For `database_risk_scan` and `xss_risk_scan`, never invent parameters. Derive method, URL, headers, body format, and fields from HAR/transcripts/API docs; if missing, ask for the specific request sample.
- For security headers, CORS, cookies, and cache policy, supplied response headers are enough for offline assessment; live scanning is not required.
- For static frontend bundles, search for API paths, token handling, source maps, hardcoded secrets, localStorage/sessionStorage usage, unsafe sinks, postMessage, and open redirect patterns.

## Reference

- Read `references/isolated-web-playbook.md` when you need artifact collection templates, internal probe packet examples, or the detailed report template.
