use clap::Parser;
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::queue;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType};
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::agent::prompt::{
    COMPACT_SYSTEM_PROMPT, COMPACTED_CONTEXT_PREFIX, default_system_prompt,
};
use crate::llm::{
    ChatMessage, ChatRole, CompletionRequest, LlmClient, LlmConfig, client_from_config,
};
use crate::tools::{ToolCall, ToolOutput, ToolRegistry, ToolSpec};

use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

const COMPACT_MAX_TOKENS: u32 = 1200;

struct SlashCommand {
    name: &'static str,
    description: &'static str,
}

#[derive(Clone, Copy)]
struct SlashCommandMatch {
    command: &'static SlashCommand,
}

const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        name: "/help",
        description: "show this help",
    },
    SlashCommand {
        name: "/compact",
        description: "compact conversation history into a summary",
    },
    SlashCommand {
        name: "/clear",
        description: "clear conversation history",
    },
    SlashCommand {
        name: "/exit",
        description: "quit",
    },
    SlashCommand {
        name: "/quit",
        description: "quit",
    },
];

#[derive(Debug, Parser)]
pub struct ChatCliArgs {
    #[arg(short, long)]
    prompt: Option<String>,

    #[arg(long)]
    temperature: Option<f32>,

    #[arg(long)]
    max_tokens: Option<u32>,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    repl: bool,
}

pub async fn run_chat_cli(default_repl: bool) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let args = ChatCliArgs::parse();
    let config = LlmConfig::from_env()?;
    if args.debug {
        eprintln!(
            "provider={:?}, model={}, base_url={}",
            config.provider,
            config.model,
            config.base_url.as_deref().unwrap_or("")
        );
    }
    let client = client_from_config(config)?;
    let repl = args.repl || (default_repl && args.prompt.is_none());
    let system = default_system_prompt().to_owned();

    if repl {
        run_repl(
            client.as_ref(),
            system,
            args.prompt,
            args.temperature,
            args.max_tokens,
        )
        .await?;
    } else {
        let prompt = args
            .prompt
            .ok_or_else(|| anyhow::anyhow!("--prompt is required unless --repl is set"))?;
        run_once(
            client.as_ref(),
            system,
            prompt,
            args.temperature,
            args.max_tokens,
        )
        .await?;
    }

    Ok(())
}

async fn run_once(
    client: &dyn LlmClient,
    system: String,
    prompt: String,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<()> {
    let mut messages = Vec::new();
    messages.push(ChatMessage::system(system));
    submit_repl_turn(client, &mut messages, prompt, temperature, max_tokens).await?;
    Ok(())
}

async fn run_repl(
    client: &dyn LlmClient,
    system: String,
    first_prompt: Option<String>,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<()> {
    let mut history = Vec::new();
    history.push(ChatMessage::system(&system));

    println!("Safety Protection Agent");
    println!("Interactive chat started. Commands: /help, /compact, /clear, /exit");
    if ReplInput::supports_line_editor() {
        println!("Type / to open the command menu, or press Tab to complete commands.");
    }

    if let Some(prompt) = first_prompt {
        submit_repl_turn(client, &mut history, prompt, temperature, max_tokens).await?;
    }

    let mut input_reader = ReplInput::new()?;

    loop {
        let Some(input) = input_reader.read_line("spa> ")? else {
            println!();
            break;
        };

        let input = input.trim().trim_start_matches('\u{feff}');
        if input.is_empty() {
            continue;
        }

        match input {
            "/exit" | "/quit" => break,
            "/help" => {
                println!("Commands:");
                print_slash_commands();
            }
            "/compact" => {
                let before = history.len();
                if compact_history(client, &mut history, &system).await? {
                    println!(
                        "Context compacted: {before} messages -> {} messages.",
                        history.len()
                    );
                } else {
                    println!("Nothing to compact yet.");
                }
            }
            "/clear" => {
                history.clear();
                history.push(ChatMessage::system(&system));
                println!("History cleared.");
            }
            _ => {
                submit_repl_turn(
                    client,
                    &mut history,
                    input.to_owned(),
                    temperature,
                    max_tokens,
                )
                .await?;
            }
        }
    }

    Ok(())
}

enum ReplInput {
    Terminal(TerminalLineReader),
    Plain,
}

impl ReplInput {
    fn supports_line_editor() -> bool {
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    }

    fn new() -> anyhow::Result<Self> {
        if !Self::supports_line_editor() {
            return Ok(Self::Plain);
        }

        Ok(Self::Terminal(TerminalLineReader::default()))
    }

    fn read_line(&mut self, prompt: &str) -> anyhow::Result<Option<String>> {
        match self {
            Self::Terminal(reader) => reader.read_line(prompt),
            Self::Plain => {
                print!("{prompt}");
                std::io::stdout().flush()?;

                let mut input = String::new();
                if std::io::stdin().read_line(&mut input)? == 0 {
                    Ok(None)
                } else {
                    Ok(Some(input))
                }
            }
        }
    }
}

#[derive(Default)]
struct TerminalLineReader {
    history: Vec<String>,
}

impl TerminalLineReader {
    fn read_line(&mut self, prompt: &str) -> anyhow::Result<Option<String>> {
        let _raw_mode = RawModeGuard::enable()?;
        let mut stdout = std::io::stdout();
        let mut buffer = Vec::new();
        let mut cursor_index = 0;
        let mut history_index = None;

        render_editor(&mut stdout, prompt, &buffer, cursor_index, true)?;

        loop {
            let Event::Key(event) = event::read()? else {
                continue;
            };
            if !matches!(event.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                continue;
            }

            match handle_editor_key(
                event,
                &mut buffer,
                &mut cursor_index,
                &mut history_index,
                &self.history,
            )? {
                EditorAction::Continue => {
                    render_editor(&mut stdout, prompt, &buffer, cursor_index, true)?;
                }
                EditorAction::Submit => {
                    let line = chars_to_string(&buffer);
                    render_editor(&mut stdout, prompt, &buffer, cursor_index, false)?;
                    write!(stdout, "\r\n")?;
                    stdout.flush()?;

                    if !line.trim().is_empty() {
                        self.history.push(line.clone());
                    }

                    return Ok(Some(line));
                }
                EditorAction::Cancel => {
                    queue!(
                        stdout,
                        cursor::MoveToColumn(0),
                        Clear(ClearType::FromCursorDown)
                    )?;
                    write!(stdout, "{prompt}\r\n")?;
                    stdout.flush()?;
                    return Ok(None);
                }
            }
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> anyhow::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

enum EditorAction {
    Continue,
    Submit,
    Cancel,
}

fn handle_editor_key(
    event: KeyEvent,
    buffer: &mut Vec<char>,
    cursor_index: &mut usize,
    history_index: &mut Option<usize>,
    history: &[String],
) -> anyhow::Result<EditorAction> {
    match event.code {
        KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => {
            Ok(EditorAction::Cancel)
        }
        KeyCode::Char('d')
            if event.modifiers.contains(KeyModifiers::CONTROL) && buffer.is_empty() =>
        {
            Ok(EditorAction::Cancel)
        }
        KeyCode::Enter => Ok(EditorAction::Submit),
        KeyCode::Char(ch) => {
            buffer.insert(*cursor_index, ch);
            *cursor_index += 1;
            *history_index = None;
            Ok(EditorAction::Continue)
        }
        KeyCode::Backspace => {
            if *cursor_index > 0 {
                *cursor_index -= 1;
                buffer.remove(*cursor_index);
            }
            *history_index = None;
            Ok(EditorAction::Continue)
        }
        KeyCode::Delete => {
            if *cursor_index < buffer.len() {
                buffer.remove(*cursor_index);
            }
            *history_index = None;
            Ok(EditorAction::Continue)
        }
        KeyCode::Left => {
            *cursor_index = cursor_index.saturating_sub(1);
            Ok(EditorAction::Continue)
        }
        KeyCode::Right => {
            if *cursor_index < buffer.len() {
                *cursor_index += 1;
            }
            Ok(EditorAction::Continue)
        }
        KeyCode::Home => {
            *cursor_index = 0;
            Ok(EditorAction::Continue)
        }
        KeyCode::End => {
            *cursor_index = buffer.len();
            Ok(EditorAction::Continue)
        }
        KeyCode::Up => {
            if !history.is_empty() {
                let next_index =
                    history_index.map_or(history.len() - 1, |index| index.saturating_sub(1));
                *history_index = Some(next_index);
                *buffer = history[next_index].chars().collect();
                *cursor_index = buffer.len();
            }
            Ok(EditorAction::Continue)
        }
        KeyCode::Down => {
            if let Some(index) = *history_index {
                if index + 1 < history.len() {
                    let next_index = index + 1;
                    *history_index = Some(next_index);
                    *buffer = history[next_index].chars().collect();
                } else {
                    *history_index = None;
                    buffer.clear();
                }
                *cursor_index = buffer.len();
            }
            Ok(EditorAction::Continue)
        }
        KeyCode::Tab => {
            complete_unique_slash_command(buffer, cursor_index);
            Ok(EditorAction::Continue)
        }
        _ => Ok(EditorAction::Continue),
    }
}

fn render_editor(
    stdout: &mut std::io::Stdout,
    prompt: &str,
    buffer: &[char],
    cursor_index: usize,
    show_menu: bool,
) -> anyhow::Result<()> {
    let line = chars_to_string(buffer);
    let menu_items = if show_menu {
        slash_menu_items(&line)
    } else {
        Vec::new()
    };
    let menu_rows = if menu_items.is_empty() {
        0
    } else {
        menu_items.len() + 1
    };

    queue!(
        stdout,
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;
    write!(stdout, "{prompt}{line}")?;

    if !menu_items.is_empty() {
        write!(stdout, "\r\n")?;
        for item in menu_items {
            write!(stdout, "\r\n  ")?;
            queue!(stdout, SetForegroundColor(Color::Cyan))?;
            write!(stdout, "{:<24}", item.command.name)?;
            queue!(stdout, ResetColor, SetForegroundColor(Color::DarkGrey))?;
            write!(stdout, "{}", item.command.description)?;
            queue!(stdout, ResetColor)?;
        }

        queue!(stdout, cursor::MoveUp(menu_rows as u16))?;
    }

    queue!(
        stdout,
        cursor::MoveToColumn(editor_cursor_column(prompt, buffer, cursor_index))
    )?;
    stdout.flush()?;
    Ok(())
}

fn chars_to_string(chars: &[char]) -> String {
    chars.iter().collect()
}

fn editor_cursor_column(prompt: &str, buffer: &[char], cursor_index: usize) -> u16 {
    let cursor_index = cursor_index.min(buffer.len());
    let width = prompt.width() + chars_display_width(&buffer[..cursor_index]);
    terminal_column(width)
}

fn chars_display_width(chars: &[char]) -> usize {
    chars
        .iter()
        .map(|ch| UnicodeWidthChar::width(*ch).unwrap_or(0))
        .sum()
}

fn terminal_column(width: usize) -> u16 {
    width.min(u16::MAX as usize) as u16
}

fn slash_menu_items(line: &str) -> Vec<SlashCommandMatch> {
    if !line.starts_with('/') || line.contains(char::is_whitespace) {
        return Vec::new();
    }

    SLASH_COMMANDS
        .iter()
        .filter(|command| command.name != "/quit")
        .filter(|command| command.name.starts_with(line))
        .map(|command| SlashCommandMatch { command })
        .collect()
}

fn complete_unique_slash_command(buffer: &mut Vec<char>, cursor_index: &mut usize) -> bool {
    if *cursor_index != buffer.len() {
        return false;
    }

    let line = chars_to_string(buffer);
    let items = slash_menu_items(&line);
    if items.len() != 1 {
        return false;
    }

    *buffer = items[0].command.name.chars().collect();
    *cursor_index = buffer.len();
    true
}

fn print_slash_commands() {
    for command in SLASH_COMMANDS {
        if command.name == "/quit" {
            continue;
        }
        println!("  {:<9} {}", command.name, command.description);
    }
}

async fn compact_history(
    client: &dyn LlmClient,
    history: &mut Vec<ChatMessage>,
    system: &str,
) -> anyhow::Result<bool> {
    let messages = compactable_messages(history, system);
    let has_dialogue = messages
        .iter()
        .any(|message| matches!(message.role, ChatRole::User | ChatRole::Assistant));

    if !has_dialogue {
        return Ok(false);
    }

    println!("Compacting {} messages...", messages.len());

    let prompt = format_compact_prompt(&messages);
    let summary = complete(
        client,
        &[
            ChatMessage::system(COMPACT_SYSTEM_PROMPT),
            ChatMessage::user(prompt),
        ],
        Some(0.2),
        Some(COMPACT_MAX_TOKENS),
    )
    .await?;
    let summary = summary.trim();
    if summary.is_empty() {
        anyhow::bail!("compact returned an empty summary");
    }

    history.clear();
    history.push(ChatMessage::system(system));
    history.push(ChatMessage::system(format!(
        "{COMPACTED_CONTEXT_PREFIX}{summary}"
    )));

    Ok(true)
}

fn compactable_messages(history: &[ChatMessage], system: &str) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    let mut skipped_original_system = false;

    for message in history {
        if !skipped_original_system
            && matches!(message.role, ChatRole::System)
            && message.content == system
        {
            skipped_original_system = true;
            continue;
        }

        messages.push(copy_message(message));
    }

    messages
}

fn format_compact_prompt(messages: &[ChatMessage]) -> String {
    let mut prompt = String::from(
        "Compact the following conversation history into a summary for future turns.\n\n",
    );

    for (index, message) in messages.iter().enumerate() {
        prompt.push_str(&format!(
            "## Message {}\nRole: {}\nContent:\n{}\n\n",
            index + 1,
            role_label(&message.role),
            message.content
        ));
    }

    prompt
}

async fn submit_repl_turn(
    client: &dyn LlmClient,
    history: &mut Vec<ChatMessage>,
    prompt: String,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<()> {
    let response = run_agent_loop(client, history, &prompt, temperature, max_tokens).await?;
    println!("{response}");
    history.push(ChatMessage::user(prompt));
    history.push(ChatMessage::assistant(response));
    Ok(())
}

async fn run_agent_loop(
    client: &dyn LlmClient,
    history: &[ChatMessage],
    prompt: &str,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<String> {
    let registry = ToolRegistry::with_builtins()?;
    let tools = registry.specs();
    let mut loop_messages = build_agent_messages(history, prompt, &tools);

    for _ in 0..6 {
        let raw = complete(
            client,
            &loop_messages,
            temperature.or(Some(0.1)),
            max_tokens,
        )
        .await?;
        let Some(decision) = parse_agent_decision(&raw) else {
            return Ok(raw);
        };

        match decision {
            AgentDecision::Ask { message } | AgentDecision::Final { message } => {
                return Ok(message);
            }
            AgentDecision::CallTool { tool_name, input } => {
                if !registry.has(&tool_name) {
                    loop_messages.push(ChatMessage::assistant(raw));
                    loop_messages.push(ChatMessage::user(format!(
                        "Tool call failed: unknown tool `{tool_name}`. Choose one of: {}.",
                        tools
                            .iter()
                            .map(|tool| tool.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                    continue;
                }

                println!("Running tool: {tool_name}");
                let output = dispatch_with_progress(&registry, ToolCall::new(&tool_name, input))
                    .await
                    .map_err(anyhow::Error::from)?;
                println!("{}", output.content);
                println!("Analyzing tool result with AI...");

                loop_messages.push(ChatMessage::assistant(raw));
                loop_messages.push(ChatMessage::user(format_tool_result_for_agent(
                    &tool_name, &output,
                )));
            }
        }
    }

    Ok("工具调用循环超过最大轮次，请补充更明确的请求信息后重试。".to_owned())
}

async fn dispatch_with_progress(
    registry: &ToolRegistry,
    call: ToolCall,
) -> anyhow::Result<crate::tools::ToolOutput> {
    let progress = Arc::new(|progress: crate::tools::ToolProgress| {
        println!(
            "Tool progress: {} {}% - {}",
            progress.tool_name, progress.percent, progress.message
        );
    });

    registry
        .dispatch_with_progress(call, progress)
        .await
        .map_err(Into::into)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum AgentDecision {
    Ask { message: String },
    CallTool { tool_name: String, input: Value },
    Final { message: String },
}

fn build_agent_messages(
    history: &[ChatMessage],
    prompt: &str,
    tools: &[ToolSpec],
) -> Vec<ChatMessage> {
    let mut messages = vec![ChatMessage::system(format_agent_loop_system_prompt(tools))];
    messages.extend(history.iter().map(copy_message));
    messages.push(ChatMessage::user(prompt));
    messages
}

fn format_agent_loop_system_prompt(tools: &[ToolSpec]) -> String {
    format!(
        "{}\n\nYou are now running inside an agent loop. You can either answer normally, ask for missing information, or call exactly one local tool.\n\nAvailable tools:\n{}\n\nDecision protocol:\nReturn exactly one JSON object and no Markdown, no code fences, no extra text.\nUse one of these shapes:\n{{\"action\":\"ask\",\"message\":\"...\"}}\n{{\"action\":\"call_tool\",\"tool_name\":\"tool_name\",\"input\":{{...}}}}\n{{\"action\":\"final\",\"message\":\"...\"}}\n\nRules:\n- Use conversation history to resolve follow-up answers. If the user first gave a URL and later says \"1.get 2.date=2026-05-13\", combine them yourself.\n- Call tools only for authorized/local/defensive testing requests.\n- If a tool needs required fields that are missing or ambiguous, ask a concise Chinese clarification question instead of guessing.\n- Never call database_risk_scan with only a bare URL. It needs at least one testable input point: query params in the URL, query_params, JSON body fields, or injectable_fields. If the user gives only a bare URL, ask for HTTP method and actual params/body fields.\n- After a tool result is provided, return a final Chinese analysis for the developer. Do not repeat full JSON.\n- For database_risk_scan, prefer GET when the user says get, include query params in the url when supplied, and avoid inventing params.\n- For http_load_test, ask for method/body/headers when not clear before calling.\n",
        default_system_prompt(),
        format_tools_for_agent(tools)
    )
}

fn format_tools_for_agent(tools: &[ToolSpec]) -> String {
    tools
        .iter()
        .map(|tool| {
            format!(
                "- name: {}\n  description: {}\n  input_schema: {}",
                tool.name, tool.description, tool.input_schema
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_agent_decision(raw: &str) -> Option<AgentDecision> {
    serde_json::from_str::<AgentDecision>(raw.trim())
        .ok()
        .or_else(|| extract_json_object(raw).and_then(|json| serde_json::from_str(&json).ok()))
}

fn extract_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end > start).then(|| raw[start..=end].to_owned())
}

fn format_tool_result_for_agent(tool_name: &str, output: &ToolOutput) -> String {
    json!({
        "type": "tool_result",
        "tool_name": tool_name,
        "content": output.content,
        "metadata": output.metadata,
    })
    .to_string()
}

async fn complete(
    client: &dyn LlmClient,
    messages: &[ChatMessage],
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<String> {
    let mut request = CompletionRequest::new(copy_messages(messages));
    if let Some(temperature) = temperature {
        request = request.with_temperature(temperature);
    }
    if let Some(max_tokens) = max_tokens {
        request = request.with_max_tokens(max_tokens);
    }

    let response = client.complete(request).await?;
    Ok(response.content)
}

fn copy_messages(messages: &[ChatMessage]) -> Vec<ChatMessage> {
    let mut copied = Vec::with_capacity(messages.len());
    for message in messages {
        copied.push(copy_message(message));
    }
    copied
}

fn copy_message(message: &ChatMessage) -> ChatMessage {
    let role = match &message.role {
        ChatRole::System => ChatRole::System,
        ChatRole::User => ChatRole::User,
        ChatRole::Assistant => ChatRole::Assistant,
    };

    ChatMessage {
        role,
        content: message.content.to_owned(),
    }
}

fn role_label(role: &ChatRole) -> &'static str {
    match role {
        ChatRole::System => "system",
        ChatRole::User => "user",
        ChatRole::Assistant => "assistant",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{ChatUsage, CompletionResponse, Result};
    use async_trait::async_trait;
    use clap::CommandFactory;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeClient {
        request: Mutex<Option<CompletionRequest>>,
    }

    #[async_trait]
    impl LlmClient for FakeClient {
        async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
            *self.request.lock().expect("fake client mutex poisoned") = Some(request);
            Ok(CompletionResponse {
                content: "User wants a compact command and SPA should keep durable context."
                    .to_string(),
                model: "fake".to_string(),
                usage: Some(ChatUsage {
                    input_tokens: None,
                    output_tokens: None,
                }),
            })
        }
    }

    #[tokio::test]
    async fn compact_history_keeps_original_system_and_adds_summary() {
        let client = FakeClient::default();
        let system = "You are a security assistant.".to_string();
        let mut history = vec![
            ChatMessage::system(&system),
            ChatMessage::user("Add /compact."),
            ChatMessage::assistant("I will implement it."),
        ];

        let compacted = compact_history(&client, &mut history, &system)
            .await
            .expect("compact should succeed");

        assert!(compacted);
        assert_eq!(history.len(), 2);
        assert!(matches!(history[0].role, ChatRole::System));
        assert_eq!(history[0].content, system);
        assert!(matches!(history[1].role, ChatRole::System));
        assert!(history[1].content.contains(COMPACTED_CONTEXT_PREFIX));
        assert!(history[1].content.contains("compact command"));

        let request = client
            .request
            .lock()
            .expect("fake client mutex poisoned")
            .take()
            .expect("compact should call the model");
        assert_eq!(request.messages.len(), 2);
        assert!(request.messages[1].content.contains("Role: user"));
        assert!(request.messages[1].content.contains("Add /compact."));
        assert!(!request.messages[1].content.contains(&system));
    }

    #[tokio::test]
    async fn compact_history_skips_when_there_is_no_dialogue() {
        let client = FakeClient::default();
        let system = "You are a security assistant.".to_string();
        let mut history = vec![ChatMessage::system(&system)];

        let compacted = compact_history(&client, &mut history, &system)
            .await
            .expect("empty compact should succeed");

        assert!(!compacted);
        assert_eq!(history.len(), 1);
        assert!(
            client
                .request
                .lock()
                .expect("fake client mutex poisoned")
                .is_none()
        );
    }

    #[test]
    fn slash_menu_shows_command_list_for_bare_slash() {
        let names: Vec<_> = slash_menu_items("/")
            .into_iter()
            .map(|item| item.command.name)
            .collect();

        assert_eq!(names, vec!["/help", "/compact", "/clear", "/exit"]);
    }

    #[test]
    fn slash_completion_completes_unique_command() {
        let mut buffer: Vec<char> = "/com".chars().collect();
        let mut cursor_index = buffer.len();

        assert!(complete_unique_slash_command(
            &mut buffer,
            &mut cursor_index
        ));
        assert_eq!(chars_to_string(&buffer), "/compact");
        assert_eq!(cursor_index, buffer.len());

        let mut unknown: Vec<char> = "/unknown".chars().collect();
        let mut unknown_cursor = unknown.len();
        assert!(!complete_unique_slash_command(
            &mut unknown,
            &mut unknown_cursor
        ));
    }

    #[test]
    fn editor_cursor_column_uses_unicode_display_width() {
        let buffer: Vec<char> = "\u{4f60}\u{597d}".chars().collect();

        assert_eq!(editor_cursor_column("spa> ", &buffer, 0), 5);
        assert_eq!(editor_cursor_column("spa> ", &buffer, 1), 7);
        assert_eq!(editor_cursor_column("spa> ", &buffer, 2), 9);
    }

    #[test]
    fn editor_cursor_column_keeps_ascii_width() {
        let buffer: Vec<char> = "hello".chars().collect();

        assert_eq!(editor_cursor_column("spa> ", &buffer, 0), 5);
        assert_eq!(editor_cursor_column("spa> ", &buffer, 5), 10);
    }

    #[test]
    fn cli_does_not_expose_system_prompt_override() {
        let mut help = Vec::new();
        ChatCliArgs::command()
            .write_long_help(&mut help)
            .expect("help should render");
        let help = String::from_utf8(help).expect("help should be utf8");

        assert!(!help.contains("--system"));
    }

    #[test]
    fn parses_agent_tool_call_decision() {
        let decision = parse_agent_decision(
            r#"{"action":"call_tool","tool_name":"database_risk_scan","input":{"url":"http://localhost/test?date=2026-05-13","method":"GET"}}"#,
        )
        .expect("decision should parse");

        match decision {
            AgentDecision::CallTool { tool_name, input } => {
                assert_eq!(tool_name, "database_risk_scan");
                assert_eq!(input["method"], "GET");
            }
            _ => panic!("expected tool call"),
        }
    }

    #[test]
    fn parses_agent_decision_inside_text() {
        let decision = parse_agent_decision(
            "```json\n{\"action\":\"ask\",\"message\":\"请提供 HTTP 方法和参数。\"}\n```",
        )
        .expect("decision should parse from fenced text");

        match decision {
            AgentDecision::Ask { message } => assert!(message.contains("HTTP")),
            _ => panic!("expected ask"),
        }
    }

    #[test]
    fn agent_prompt_includes_tool_schemas_and_followup_rule() {
        let tools = vec![ToolSpec::new(
            "database_risk_scan",
            "Probe database risk.",
            json!({"type":"object","required":["url"]}),
        )];
        let prompt = format_agent_loop_system_prompt(&tools);

        assert!(prompt.contains("database_risk_scan"));
        assert!(prompt.contains("1.get 2.date=2026-05-13"));
        assert!(prompt.contains("\"action\":\"call_tool\""));
    }
}
