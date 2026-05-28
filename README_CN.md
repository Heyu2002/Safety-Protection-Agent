# Safety-Protection-Agent

[English](README.md)

一个面向已公开漏洞扫描与分析的安全防护 Agent。

## LLM API 适配层

项目当前先提供一层轻量 Rust LLM 适配器。后续 Agent 逻辑只依赖统一的
`LlmClient` trait，不直接绑定某个模型厂商 SDK。

已支持的 provider：

- `openai`：OpenAI Chat Completions API
- `openai-compatible`：兼容 OpenAI Chat Completions 的接口
- `openai-responses`：OpenAI Responses API
- `codex-chatgpt`：复用本机 Codex 的 ChatGPT 登录态
- `kimi`：Kimi Code / Kimi CLI 订阅接口
- `moonshot`：Moonshot / Kimi 开放平台接口
- `anthropic`：Anthropic Messages API
- `gemini`：Google Gemini Generate Content API
- `ollama`：本地 Ollama Chat API

## 快速开始

```powershell
Copy-Item .env.example .env
```

编辑 `.env` 后运行：

```powershell
cargo run --bin spa
```

`spa` 启动器会默认进入带上下文历史的交互式 CLI。

Windows 下可以一键本地安装：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

这个脚本会自动把 `%USERPROFILE%\.cargo\bin` 加入当前用户 PATH，并安装 `spa` / `spa-chat`。安装后可以直接运行：

```powershell
spa
```

也可以直接传入单次问题：

```powershell
cargo run --bin spa -- --prompt "给我一个CVE漏洞初筛流程"
```

REPL 内可以使用 `/compact` 压缩当前上下文，使用 `/clear` 清空上下文，使用 `/exit` 退出。
在交互式终端里输入 `/` 会展开命令菜单，也可以按 Tab 补全斜杠命令。

底层的 `spa-chat` 命令仍然保留：

```powershell
cargo run --bin spa-chat -- --repl
```

## Agent 系统提示词

默认的 Safety Protection Agent 系统提示词位于 `src/agent/prompts/default.md`。
压缩上下文使用的提示词位于 `src/agent/prompts/compact.md`。
`src/agent/prompt.rs` 只负责通过 `include_str!` 把这些 Markdown 提示词暴露给 Rust 代码。

系统提示词定义了 agent 的产品身份、防御安全定位、工作方式、上下文规则和安全边界。provider 层仍然保持通用，只负责调用模型 API。

系统提示词不允许通过 CLI 参数或 `.env` 覆盖，因为它属于 agent 的安全边界。只有在产品行为需要正式变更时，才应该在代码里修改。

## Skills

Codex 风格的真实 skill 位于 `skills/`。通用约定保留在 `skills/CONVENTIONS.md`，`skills/` 下不再放脚手架模板目录。

创建新的 skill 骨架：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

## Agent Red-Team Lab MCP

项目包含独立的本地 agent 红队靶场 MCP server：

```powershell
cargo run --bin spa-agent-lab-mcp
```

它面向本地 MCP-compatible agent，专门测试工具越权、canary 外发、恶意上下文、敏感工具调用和可选容器 shell 场景。它不暴露普通 web 漏洞扫描工具。

核心工具包括 `agent_lab_get_task`、`agent_lab_read_file`、`agent_lab_write_file`、`agent_lab_read_sensitive`、`agent_lab_http_request`、`agent_lab_run_shell`、`agent_lab_published_probe` 和 `agent_lab_complete`。实验结束后 `agent_lab_complete` 会返回 Markdown 报告路径。

第一版不使用真实 secret、真实用户文件或真实外网。Docker/Podman 是可选增强；没有容器时 shell 场景会标记为 skipped。

对于已经发布的 agent API 或产品端点，使用 `agent_lab_published_probe`。该模式要求 `authorization_confirmed: true`，只发送合成 canary 和低副作用 probe，默认每个场景最多 3 次请求、总计最多 30 次请求，并在确认最小证据后停止。

如果需要查看实际 provider、模型和 base URL：

```powershell
cargo run --bin spa-chat -- --debug --prompt "你好"
```

## 复用本机 Codex 登录态

如果你已经在本机 Codex 登录了 ChatGPT 账号，可以使用：

```env
LLM_PROVIDER=codex-chatgpt
CODEX_MODEL=gpt-5.5
CODEX_CHATGPT_BASE_URL=https://chatgpt.com/backend-api/codex
```

这个模式会读取：

```text
~/.codex/auth.json
```

然后调用：

```text
POST https://chatgpt.com/backend-api/codex/responses
```

如果你的 shell 访问 `chatgpt.com` 需要代理，可以在 `.env` 中配置：

```env
HTTPS_PROXY=http://127.0.0.1:7960
HTTP_PROXY=http://127.0.0.1:7960
```

端口需要与你本机代理软件保持一致。

## 中转站配置

如果中转站支持 OpenAI Chat Completions：

```env
LLM_PROVIDER=openai-compatible
OPENAI_API_KEY=你的中转站key
OPENAI_MODEL=你的模型名
OPENAI_BASE_URL=https://你的中转站域名/v1
```

中转站需要提供：

```text
POST /v1/chat/completions
```

如果中转站只支持 OpenAI Responses API：

```env
LLM_PROVIDER=openai-responses
OPENAI_API_KEY=你的中转站key
OPENAI_MODEL=你的模型名
OPENAI_BASE_URL=https://你的中转站域名/v1
```

中转站需要提供：

```text
POST /v1/responses
```

如果中转站给的是自定义模型配置，按它声明的 `provider` 来选 `LLM_PROVIDER`，不要把所有模型都当成 `openai-compatible`。也可以使用通用变量 `LLM_API_KEY`、`LLM_MODEL`、`LLM_BASE_URL`，适用于 `openai`、`openai-compatible`、`openai-completions`、`openai-responses`、`anthropic` 和 `gemini`。设置了 `LLM_*` 时，它们会优先于系统里可能残留的 `OPENAI_*` 等专用变量。

例如中转站声明为 OpenAI Responses 的模型：

```env
LLM_PROVIDER=openai-responses
LLM_API_KEY=你的中转站key
LLM_MODEL=你的Responses模型名
LLM_BASE_URL=https://你的中转站域名/v1
```

如果 Chat Completions 中转站或模型不接受 `tools`、`tool_choice`、`parallel_tool_calls` 这类原生工具调用参数，可以关闭原生工具调用，改走 SPA 的 fallback agent 协议：

```env
LLM_NATIVE_TOOLS=false
```

例如中转站声明为 `provider: "anthropic"` 的模型：

```env
LLM_PROVIDER=anthropic
LLM_API_KEY=你的中转站key
LLM_MODEL=你的Anthropic兼容模型名
LLM_BASE_URL=https://你的中转站域名
```

Anthropic 兼容接口的 base URL 可以写 API 根地址或 `/v1` 地址，程序会自动拼到 Messages endpoint。

## Kimi 配置

Kimi Code / Kimi CLI 订阅使用 `api.kimi.com` 账号体系：

```env
LLM_PROVIDER=kimi
KIMI_API_KEY=sk-...
KIMI_MODEL=kimi-for-coding
KIMI_BASE_URL=https://api.kimi.com/coding/v1
```

Moonshot / Kimi 开放平台是另一套账号体系：

```env
LLM_PROVIDER=moonshot
MOONSHOT_API_KEY=sk-...
MOONSHOT_MODEL=kimi-k2.6
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
```

两套 key 不通用。

## 代码调用

```rust
use safety_protection_agent::llm::{
    ChatMessage, CompletionRequest, LlmClient, client_from_env,
};

#[tokio::main]
async fn main() -> safety_protection_agent::llm::Result<()> {
    dotenvy::dotenv().ok();

    let client = client_from_env()?;
    let response = client
        .complete(CompletionRequest::new(vec![
            ChatMessage::system("你是一个安全漏洞分析助手。"),
            ChatMessage::user("用一段话总结 CVE-2024-3094。"),
        ]))
        .await?;

    println!("{}", response.content);
    Ok(())
}
```
