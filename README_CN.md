# Safety Protection Agent

[English](README.md)

Safety Protection Agent（`spa`）是一个基于 Rust 的终端安全 Agent，面向授权防御测试、本地靶场验证和可复现漏洞评估。它集成了 Codex 风格交互循环、模型工具调用、MCP 集成、运行时 Skills，以及一组低影响安全检查工具。

`spa` 只适用于自有系统、本地实验环境和明确授权目标。不要将它用于未授权访问、隐蔽驻留、数据窃取或绕过授权边界。

## 快速开始

在仓库内直接运行：

```powershell
Copy-Item .env.example .env
cargo run --bin spa
```

Windows 本地安装：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
spa
```

常用 REPL 命令：

```text
/help
/compact
/clear
/mcp
/exit
```

## 配置

在 `.env` 中配置模型 provider。支持的 provider 和常见中转配置示例见 `.env.example`。

最小本地/默认配置：

```env
LLM_PROVIDER=codex-chatgpt
```

OpenAI 兼容接口或中转配置：

```env
LLM_PROVIDER=openai-responses
LLM_API_KEY=your-key
LLM_MODEL=your-model
LLM_BASE_URL=https://provider.example.com/v1
```

如果 Chat Completions 兼容接口不接受原生工具参数，可以关闭原生工具载荷：

```env
LLM_NATIVE_TOOLS=false
```

如需允许报告工具写入已完成的 Markdown 报告，设置：

```env
SPA_AGENT_REPORT_DIR=reports
```

只有当模型在报告完成后显式调用 `generate_markdown_report` 时，才会写入报告文件。

## MCP 集成

通过 CLI 注册 MCP server：

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

已配置的 MCP 工具会在每个 agent turn 开始时暴露给模型，由模型决定是否调用。

`spa` 也可以作为 MCP server 运行：

```powershell
cargo run --bin spa-mcp
```

Agent 红队实验 MCP server 单独运行：

```powershell
cargo run --bin spa-agent-lab-mcp
```

## 运行时 Skills

运行时 skills 位于 `skills/`。Host 会把 skill catalog 暴露给模型，模型选择相关 skill 后，运行时再把对应的 `SKILL.md` 正文加入 agent 上下文。

内置 skills：

- `web-vulnerability-discovery`
- `isolated-web-security-assessment`
- `agent-redteam-lab`

创建新 skill：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

## 内置工具

内置工具聚焦于证据驱动、低影响的安全检查和报告生成：

- `http_security_headers_scan`
- `database_risk_scan`
- `xss_risk_scan`
- `weak_session_id_scan`
- `http_load_test`
- `generate_markdown_report`

正式报告应包含范围、覆盖面、攻击类型、发现、证据和修复建议。

## 评估快照

当前仓库内的 OWASP Benchmark 对比覆盖了 truth set 中 2,740 个用例里的 30 个公共用例。本工作区内的源报告路径：
`target/owasp-benchmark-agent-comparison-30/comparison.md`。

生成时间：`2026-05-29T19:51:11.1365400+08:00`

| Agent | Cases | Correct | TP | FP | TN | FN | Inconclusive | Avg seconds/case | Accuracy | Estimated full hours | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| spa | 30 | 22 | 15 | 2 | 7 | 2 | 4 | 71.4 | 0.7333 | 54.3 | 0.8824 |
| codex | 30 | 23 | 14 | 1 | 9 | 2 | 4 | 394.3 | 0.7667 | 300.1 | 0.875 |

## OWASP Benchmark 评估

OWASP Benchmark 可以作为可复现 Web 漏洞评估目标。先单独启动 Benchmark 应用，然后运行一个小规模 SPA 评估集：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\eval-owasp-benchmark.ps1 `
  -BaseUrl https://localhost:8443/benchmark `
  -ExpectedResultsCsv path\to\expectedresults.csv `
  -Limit 10
```

使用 `-DryRun` 可以只生成 prompts 和结果文件，不调用 `spa`。

## 开发

提交代码变更前运行格式检查和测试：

```powershell
cargo fmt --check
cargo test
```

查看 provider 调试输出：

```powershell
cargo run --bin spa -- --debug
```

主要路径：

```text
src/cli.rs                 CLI 和 agent loop
src/llm/                   Provider 抽象
src/tools/                 内置工具
src/mcp_client.rs          MCP client 集成
src/agent/prompts/         系统提示词
skills/                    运行时 skills
scripts/                   安装、skill 和评估脚本
target/                    生成的构建和评估输出
```

默认系统提示词属于 agent 安全边界的一部分，不允许通过 `.env` 或 CLI 参数覆盖。
