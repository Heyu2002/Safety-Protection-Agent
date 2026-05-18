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
