# Safety Protection Agent

[English](README.md)

`spa` 是一个 Rust 安全防护 Agent，用于授权场景下的防御测试、实验室验证和
安全分析。它提供 Codex 风格的终端交互、模型工具调用、MCP 集成、运行时
skills，以及一组低影响安全检测工具。

本项目只面向已授权目标。不要用于未授权访问、隐蔽驻留、数据窃取或绕过授权。

## 安装运行

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

在 `.env` 中配置模型 provider。支持的 provider 和常见中转站写法见
`.env.example`。

常见配置：

```env
LLM_PROVIDER=codex-chatgpt
```

```env
LLM_PROVIDER=openai-responses
LLM_API_KEY=your-key
LLM_MODEL=your-model
LLM_BASE_URL=https://provider.example.com/v1
```

如果 Chat Completions 兼容接口不支持原生工具参数：

```env
LLM_NATIVE_TOOLS=false
```

报告输出目录：

```env
SPA_AGENT_REPORT_DIR=reports
```

只有模型显式调用 `generate_markdown_report` 时才会写入报告文件。

## MCP

注册 MCP server：

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

已配置 MCP 会在每个 agent turn 开始时暴露工具 schema，由模型决定是否调用。

SPA 也可以作为 MCP server 运行：

```powershell
cargo run --bin spa-mcp
```

Agent 红队靶场 MCP server：

```powershell
cargo run --bin spa-agent-lab-mcp
```

## Skills

运行时 skills 位于 `skills/`。host 只把 skill catalog 暴露给模型，模型选择
需要的 skill 后，runtime 再注入对应 `SKILL.md` 正文。

内置 skills：

- `web-vulnerability-discovery`
- `isolated-web-security-assessment`
- `agent-redteam-lab`

创建新 skill：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

## Tools

内置工具：

- `http_security_headers_scan`
- `database_risk_scan`
- `xss_risk_scan`
- `weak_session_id_scan`
- `http_load_test`
- `generate_markdown_report`

工具行为应保持低影响、证据驱动。正式报告应包含覆盖范围、攻击类型、发现和修复
建议。

## 开发

```powershell
cargo fmt --check
cargo test
```

查看 provider 调试信息：

```powershell
cargo run --bin spa -- --debug
```

主要路径：

```text
src/cli.rs                 CLI 和 agent loop
src/llm/                   provider 抽象
src/tools/                 内置工具
src/mcp_client.rs          MCP client 集成
src/agent/prompts/         系统提示词
skills/                    运行时 skills
```

默认系统提示词属于 agent 安全边界，不允许通过 `.env` 或 CLI 参数覆盖。
