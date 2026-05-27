use clap::{Args, Parser, Subcommand};
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::queue;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType};
use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::agent::prompt::{
    COMPACT_SYSTEM_PROMPT, COMPACTED_CONTEXT_PREFIX, default_system_prompt,
};
use crate::llm::{
    AgentToolCall, AgentToolSpec, AgentToolTranscriptItem, AgentTurnRequest, AgentTurnResponse,
    ChatMessage, ChatRole, CompletionDeltaCallback, CompletionRequest, LlmClient, LlmConfig,
    client_from_config,
};
use crate::mcp_client::RemoteMcpToolbox;
use crate::mcp_client::{
    RemoteMcpServerConfig, add_stdio_mcp_server, load_remote_mcp_configs, spa_config_path,
};
use crate::tools::{ToolCall, ToolOutput, ToolRegistry, ToolSpec};

use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

const COMPACT_MAX_TOKENS: u32 = 1200;
const USER_PROMPT: &str = "user> ";
const AGENT_PREFIX: &str = "agent> ";
const USER_PROMPT_COLOR: Color = Color::Rgb {
    r: 80,
    g: 170,
    b: 255,
};
const AGENT_PROMPT_COLOR: Color = Color::Green;

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
        name: "/mcp",
        description: "list configured MCP servers",
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
    #[command(subcommand)]
    command: Option<CliCommand>,

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

#[derive(Debug, Subcommand)]
enum CliCommand {
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Add(McpAddArgs),
    List,
}

#[derive(Debug, Args)]
struct McpAddArgs {
    name: String,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

pub async fn run_chat_cli(default_repl: bool) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let args = ChatCliArgs::parse();
    if let Some(command) = args.command {
        return run_cli_command(command).await;
    }

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

async fn run_cli_command(command: CliCommand) -> anyhow::Result<()> {
    match command {
        CliCommand::Mcp { command } => match command {
            McpCommand::Add(args) => {
                let path = add_stdio_mcp_server(&args.name, &args.command)?;
                println!("Added MCP server `{}` to {}.", args.name, path.display());
                println!("Command: {}", args.command.join(" "));
                println!("Run `spa mcp list` or start `spa` and use `/mcp` to verify servers.");
                Ok(())
            }
            McpCommand::List => {
                print_mcp_servers(true)?;
                Ok(())
            }
        },
    }
}

fn print_mcp_servers(show_config_path: bool) -> anyhow::Result<()> {
    let configs = load_remote_mcp_configs()?;
    if show_config_path {
        println!("MCP config: {}", spa_config_path().display());
    } else {
        println!("MCP servers:");
    }
    if configs.is_empty() {
        println!("  no MCP servers configured.");
        return Ok(());
    }

    let name_width = configs
        .iter()
        .map(|config| UnicodeWidthStr::width(config.name.as_str()))
        .max()
        .unwrap_or(0)
        .max("名称".width());
    let desc_width = configs
        .iter()
        .map(|config| UnicodeWidthStr::width(mcp_server_description(config).as_str()))
        .max()
        .unwrap_or(0)
        .max("描述".width())
        .min(88);

    println!("  {}", mcp_table_separator(name_width, desc_width));
    println!(
        "  | {} | {} |",
        pad_display("名称", name_width),
        pad_display("描述", desc_width)
    );
    println!("  {}", mcp_table_separator(name_width, desc_width));
    for config in &configs {
        let description = mcp_server_description(config);
        println!(
            "  | {} | {} |",
            pad_display(&config.name, name_width),
            pad_display(&truncate_display(&description, desc_width), desc_width)
        );
    }
    println!("  {}", mcp_table_separator(name_width, desc_width));

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
    println!("Interactive chat started. Commands: /help, /compact, /clear, /mcp, /exit");
    if ReplInput::supports_line_editor() {
        println!("Type / to open the command menu, or press Tab to complete commands.");
    }

    if let Some(prompt) = first_prompt {
        submit_repl_turn(client, &mut history, prompt, temperature, max_tokens).await?;
    }

    let mut input_reader = ReplInput::new()?;

    loop {
        let Some(input) = input_reader.read_line(USER_PROMPT)? else {
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
            "/mcp" => {
                print_mcp_servers(false)?;
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
                let mut stdout = std::io::stdout();
                write_colored_prompt(&mut stdout, prompt, USER_PROMPT_COLOR)?;
                stdout.flush()?;

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
                    write_colored_prompt(&mut stdout, prompt, USER_PROMPT_COLOR)?;
                    write!(stdout, "\r\n")?;
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
    write_colored_prompt(stdout, prompt, USER_PROMPT_COLOR)?;
    write!(stdout, "{line}")?;

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

fn write_colored_prompt(
    stdout: &mut std::io::Stdout,
    prompt: &str,
    color: Color,
) -> anyhow::Result<()> {
    queue!(stdout, SetForegroundColor(color))?;
    write!(stdout, "{prompt}")?;
    queue!(stdout, ResetColor)?;
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

fn mcp_table_separator(name_width: usize, desc_width: usize) -> String {
    format!(
        "+-{}-+-{}-+",
        "-".repeat(name_width),
        "-".repeat(desc_width)
    )
}

fn mcp_server_description(config: &crate::mcp_client::RemoteMcpServerConfig) -> String {
    match config.transport {
        crate::mcp_client::RemoteMcpTransport::Stdio => {
            let command = config.command.as_deref().unwrap_or_default();
            if config.args.is_empty() {
                format!("stdio: {command}")
            } else {
                format!("stdio: {command} {}", config.args.join(" "))
            }
        }
        crate::mcp_client::RemoteMcpTransport::StreamableHttp => format!(
            "streamable-http: {}",
            config.url.as_deref().unwrap_or_default()
        ),
    }
}

fn pad_display(value: &str, width: usize) -> String {
    let current = UnicodeWidthStr::width(value);
    if current >= width {
        value.to_owned()
    } else {
        format!("{}{}", value, " ".repeat(width - current))
    }
}

fn truncate_display(value: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(value) <= max_width {
        return value.to_owned();
    }
    if max_width <= 1 {
        return "…".to_owned();
    }

    let mut output = String::new();
    let mut width = 0usize;
    for ch in value.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + ch_width + 1 > max_width {
            break;
        }
        output.push(ch);
        width += ch_width;
    }
    output.push('…');
    output
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
    let summary = complete_with_thinking(
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
    if !response.already_displayed {
        display_agent_message_streamed(&response.message).await;
    }
    history.push(ChatMessage::user(prompt));
    history.push(ChatMessage::assistant(response.message));
    Ok(())
}

#[derive(Debug)]
struct AgentLoopResponse {
    message: String,
    already_displayed: bool,
}

async fn run_agent_loop(
    client: &dyn LlmClient,
    history: &[ChatMessage],
    prompt: &str,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<AgentLoopResponse> {
    let registry = ToolRegistry::with_builtins()?;
    let remote_mcp_configs = load_remote_mcp_configs().unwrap_or_default();
    let mut remote_mcp = LazyRemoteMcp::new(remote_mcp_configs);
    if should_eager_connect_mcp(prompt) {
        let _ = remote_mcp.connect_if_needed().await;
    }
    let tools = combined_tool_specs(&registry, remote_mcp.status());
    let active_skill_context = load_active_skill_context(prompt).unwrap_or_default();

    let response = if client.supports_native_tools() {
        run_native_agent_loop(
            client,
            history,
            prompt,
            temperature,
            max_tokens,
            &registry,
            &mut remote_mcp,
            &tools,
            &active_skill_context,
        )
        .await
    } else {
        run_fallback_agent_loop(
            client,
            history,
            prompt,
            temperature,
            max_tokens,
            &registry,
            &mut remote_mcp,
            &tools,
            &active_skill_context,
        )
        .await
    };

    remote_mcp.shutdown().await;
    response
}

fn combined_tool_specs(registry: &ToolRegistry, remote_mcp: &RemoteMcpToolbox) -> Vec<ToolSpec> {
    let mut tools = registry.specs();
    tools.extend(remote_mcp.specs());
    tools.sort_by(|left, right| left.name.cmp(&right.name));
    tools
}

fn should_eager_connect_mcp(prompt: &str) -> bool {
    let prompt = prompt.to_ascii_lowercase();
    ["mcp", "chrome", "devtools", "browser"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
        || prompt.contains("浏览器")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSkill {
    name: String,
    description: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct RuntimeSkillFrontmatter {
    name: String,
    description: String,
}

fn load_active_skill_context(prompt: &str) -> anyhow::Result<String> {
    let Some(root) = find_skills_root() else {
        return Ok(String::new());
    };
    let mut skills = Vec::new();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let skill_path = entry.path().join("SKILL.md");
        if !skill_path.is_file() {
            continue;
        }
        let raw = fs::read_to_string(skill_path)?;
        let Some(skill) = parse_runtime_skill(&raw) else {
            continue;
        };
        if runtime_skill_matches(prompt, &skill) {
            skills.push(skill);
        }
    }

    skills.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(format_active_skill_context(&skills))
}

fn find_skills_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("skills");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn parse_runtime_skill(raw: &str) -> Option<RuntimeSkill> {
    let (frontmatter, body) = split_markdown_frontmatter(raw)?;
    let frontmatter = serde_yml::from_str::<RuntimeSkillFrontmatter>(frontmatter).ok()?;
    let name = frontmatter.name.trim().to_owned();
    let description = frontmatter.description.trim().to_owned();

    if !is_valid_skill_name(&name) || description.is_empty() {
        return None;
    }

    Some(RuntimeSkill {
        name,
        description,
        body: body.trim().to_owned(),
    })
}

fn split_markdown_frontmatter(raw: &str) -> Option<(&str, &str)> {
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let raw = raw
        .strip_prefix("---\r\n")
        .or_else(|| raw.strip_prefix("---\n"))?;
    let mut offset = 0;

    for line in raw.split_inclusive('\n') {
        let marker = line.trim_end_matches(&['\r', '\n'][..]);
        if marker == "---" {
            let body_start = offset + line.len();
            return Some((&raw[..offset], &raw[body_start..]));
        }
        offset += line.len();
    }

    let marker = raw[offset..].trim_end_matches('\r');
    (marker == "---").then_some((&raw[..offset], ""))
}

fn is_valid_skill_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let bytes = name.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn runtime_skill_matches(prompt: &str, skill: &RuntimeSkill) -> bool {
    let prompt_lower = prompt.to_lowercase();
    if prompt_lower.contains(&format!("${}", skill.name))
        || prompt_lower.contains(&skill.name)
        || prompt_lower.contains(&skill.name.replace('-', " "))
    {
        return true;
    }

    if skill.name == "web-vulnerability-discovery" && has_web_vulnerability_intent(prompt) {
        return true;
    }

    let prompt_tokens = ascii_tokens(prompt);
    if prompt_tokens.is_empty() {
        return false;
    }
    let description_tokens = ascii_tokens(&skill.description);
    prompt_tokens
        .intersection(&description_tokens)
        .take(2)
        .count()
        >= 2
}

fn has_web_vulnerability_intent(prompt: &str) -> bool {
    let prompt = prompt.to_lowercase();
    let web_signal = [
        "http://",
        "https://",
        "web",
        "site",
        "url",
        "网站",
        "网页",
        "页面",
        "靶场",
        "浏览器",
    ]
    .iter()
    .any(|needle| prompt.contains(needle));
    let vulnerability_signal = [
        "vulnerability",
        "vuln",
        "security",
        "xss",
        "sqli",
        "session",
        "redirect",
        "漏洞",
        "攻击",
        "风险",
        "探测",
        "挖掘",
        "测试",
        "注入",
        "弱点",
    ]
    .iter()
    .any(|needle| prompt.contains(needle));

    web_signal && vulnerability_signal
}

fn ascii_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let token = token.to_ascii_lowercase();
            (token.len() >= 4).then_some(token)
        })
        .collect()
}

fn format_active_skill_context(skills: &[RuntimeSkill]) -> String {
    if skills.is_empty() {
        return String::new();
    }

    let mut output = String::from("# Active Skills\n\n");
    for skill in skills {
        output.push_str(&format!(
            "## ${}\n\nDescription: {}\n\n{}\n\n",
            skill.name, skill.description, skill.body
        ));
    }
    output.trim().to_owned()
}

async fn run_fallback_agent_loop(
    client: &dyn LlmClient,
    history: &[ChatMessage],
    prompt: &str,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    registry: &ToolRegistry,
    remote_mcp: &mut LazyRemoteMcp,
    tools: &[ToolSpec],
    active_skill_context: &str,
) -> anyhow::Result<AgentLoopResponse> {
    let mut loop_messages = build_agent_messages(
        history,
        prompt,
        tools,
        remote_mcp.status(),
        active_skill_context,
    );
    let mut tool_call_signatures = HashSet::new();

    loop {
        let raw = complete_with_thinking_retrying_temperature(
            client,
            &loop_messages,
            temperature.or(Some(0.1)),
            max_tokens,
        )
        .await?;
        let Some(decision) = parse_agent_decision(&raw) else {
            loop_messages.push(ChatMessage::assistant(raw.clone()));
            loop_messages.push(ChatMessage::user(format_missing_decision_prompt(&raw)));
            continue;
        };

        match decision {
            AgentDecision::Ask { message } => {
                return Ok(AgentLoopResponse {
                    message,
                    already_displayed: false,
                });
            }
            AgentDecision::Final { message } => {
                return Ok(AgentLoopResponse {
                    message,
                    already_displayed: false,
                });
            }
            AgentDecision::CallTool { tool_name, input } => {
                if !registry.has(&tool_name) && !remote_mcp.maybe_has_name(&tool_name) {
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

                let call_signature = format!(
                    "{}:{}",
                    tool_name,
                    serde_json::to_string(&input).unwrap_or_else(|_| input.to_string())
                );
                if !tool_call_signatures.insert(call_signature) {
                    loop_messages.push(ChatMessage::assistant(raw));
                    loop_messages.push(ChatMessage::user(format!(
                        "Repeated tool call skipped: `{tool_name}` with the same input was already executed. Use the existing tool observation and return a final Chinese analysis now."
                    )));
                    continue;
                }

                let output = if registry.has(&tool_name) {
                    dispatch_with_progress(&registry, ToolCall::new(&tool_name, input))
                        .await
                        .map_err(anyhow::Error::from)?
                } else {
                    render_tool_spinner_until(&tool_name, remote_mcp.call(&tool_name, input))
                        .await?
                };

                loop_messages.push(ChatMessage::assistant(raw));
                loop_messages.push(ChatMessage::user(format_tool_result_for_agent(
                    &tool_name, &output,
                )));
            }
        }
    }
}

async fn run_native_agent_loop(
    client: &dyn LlmClient,
    history: &[ChatMessage],
    prompt: &str,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    registry: &ToolRegistry,
    remote_mcp: &mut LazyRemoteMcp,
    tools: &[ToolSpec],
    active_skill_context: &str,
) -> anyhow::Result<AgentLoopResponse> {
    let messages = build_native_agent_messages(
        history,
        prompt,
        tools,
        remote_mcp.status(),
        active_skill_context,
    );
    let native_tools: Vec<AgentToolSpec> =
        tools.iter().map(agent_tool_spec_from_tool_spec).collect();
    let mut input_items = Vec::new();
    let mut tool_call_signatures = HashSet::new();
    let renderer = StreamingAgentRenderer::default();
    let mut final_content = String::new();

    loop {
        let mut request = AgentTurnRequest::new(messages.clone(), native_tools.clone())
            .with_input_items(input_items.clone());
        if let Some(temperature) = temperature.or(Some(0.1)) {
            request = request.with_temperature(temperature);
        }
        if let Some(max_tokens) = max_tokens {
            request = request.with_max_tokens(max_tokens);
        }

        let displayed_before = renderer.delta_count();
        let spinner = SpinnerHandle::start("thinking");
        renderer.set_spinner(spinner.clone());
        let renderer_state = renderer.shared_state();
        let on_delta: CompletionDeltaCallback = Arc::new(move |delta| {
            if let Ok(mut state) = renderer_state.lock() {
                state.render_delta(delta);
            }
        });
        let turn = complete_agent_turn_retrying_temperature(client, request, on_delta).await?;
        spinner.stop();
        renderer.clear_spinner();
        renderer.finish_message();
        let final_turn_displayed = renderer.delta_count() > displayed_before;

        if !turn.content.trim().is_empty() {
            final_content = turn.content.clone();
        }
        input_items.extend(turn.output_items);

        if turn.tool_calls.is_empty() {
            return Ok(AgentLoopResponse {
                message: final_content,
                already_displayed: final_turn_displayed,
            });
        }

        for tool_call in turn.tool_calls {
            let call_signature = format!(
                "{}:{}",
                tool_call.name,
                serde_json::to_string(&tool_call.input)
                    .unwrap_or_else(|_| tool_call.input.to_string())
            );
            let output = if !registry.has(&tool_call.name)
                && !remote_mcp.maybe_has_name(&tool_call.name)
            {
                format!("Tool call failed: unknown tool `{}`.", tool_call.name)
            } else if !tool_call_signatures.insert(call_signature) {
                format!(
                    "Repeated tool call skipped: `{}` with the same input was already executed.",
                    tool_call.name
                )
            } else {
                execute_agent_tool_call(registry, remote_mcp, &tool_call).await?
            };
            input_items.push(AgentToolTranscriptItem::tool_result(
                tool_call.call_id,
                output,
            ));
        }
    }
}

async fn execute_agent_tool_call(
    registry: &ToolRegistry,
    remote_mcp: &mut LazyRemoteMcp,
    tool_call: &AgentToolCall,
) -> anyhow::Result<String> {
    let output = if registry.has(&tool_call.name) {
        dispatch_with_progress(
            registry,
            ToolCall {
                id: tool_call.call_id.clone(),
                name: tool_call.name.clone(),
                input: tool_call.input.clone(),
            },
        )
        .await
        .map_err(anyhow::Error::from)?
    } else {
        render_tool_spinner_until(
            &tool_call.name,
            remote_mcp.call(&tool_call.name, tool_call.input.clone()),
        )
        .await?
    };

    Ok(format_tool_result_for_agent(&tool_call.name, &output))
}

fn agent_tool_spec_from_tool_spec(tool: &ToolSpec) -> AgentToolSpec {
    AgentToolSpec::new(
        tool.name.clone(),
        tool.description.clone(),
        tool.input_schema.clone(),
    )
}

struct LazyRemoteMcp {
    configs: Vec<RemoteMcpServerConfig>,
    connected: Option<RemoteMcpToolbox>,
    status: RemoteMcpToolbox,
}

impl LazyRemoteMcp {
    fn new(configs: Vec<RemoteMcpServerConfig>) -> Self {
        let status = if configs.is_empty() {
            RemoteMcpToolbox::empty()
        } else {
            RemoteMcpToolbox::with_connection_error(format!(
                "{} MCP server(s) configured. Remote MCP tools will connect lazily when requested.",
                configs.len()
            ))
        };

        Self {
            configs,
            connected: None,
            status,
        }
    }

    fn status(&self) -> &RemoteMcpToolbox {
        self.connected.as_ref().unwrap_or(&self.status)
    }

    fn maybe_has_name(&self, name: &str) -> bool {
        self.status().has(name) || name.starts_with("mcp__")
    }

    async fn call(&mut self, name: &str, input: Value) -> anyhow::Result<ToolOutput> {
        let toolbox = self.connect_if_needed().await?;
        toolbox.call(name, input).await
    }

    async fn connect_if_needed(&mut self) -> anyhow::Result<&RemoteMcpToolbox> {
        if self.connected.is_none() {
            let configs = self.configs.clone();
            self.connected = Some(RemoteMcpToolbox::connect(configs).await?);
        }

        Ok(self
            .connected
            .as_ref()
            .expect("connected MCP toolbox exists"))
    }

    async fn shutdown(self) {
        if let Some(toolbox) = self.connected {
            toolbox.shutdown().await;
        }
    }
}

#[derive(Default)]
struct StreamingAgentRenderer {
    state: Arc<Mutex<StreamingAgentRendererState>>,
}

impl StreamingAgentRenderer {
    fn shared_state(&self) -> Arc<Mutex<StreamingAgentRendererState>> {
        Arc::clone(&self.state)
    }

    fn set_spinner(&self, spinner: SpinnerHandle) {
        if let Ok(mut state) = self.state.lock() {
            state.set_spinner(spinner);
        }
    }

    fn clear_spinner(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.clear_spinner();
        }
    }

    fn finish_message(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.finish_message();
        }
    }

    fn delta_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.delta_count)
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct StreamingAgentRendererState {
    active_message: bool,
    delta_count: usize,
    spinner: Option<SpinnerHandle>,
}

impl StreamingAgentRendererState {
    fn set_spinner(&mut self, spinner: SpinnerHandle) {
        self.clear_spinner();
        self.spinner = Some(spinner);
    }

    fn clear_spinner(&mut self) {
        if let Some(spinner) = self.spinner.take() {
            spinner.stop();
        }
    }

    fn render_delta(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }

        let mut stdout = std::io::stdout();
        if !self.active_message {
            self.clear_spinner();
            let _ = queue!(
                stdout,
                SetForegroundColor(AGENT_PROMPT_COLOR),
                cursor::MoveToColumn(0)
            );
            let _ = write!(stdout, "{AGENT_PREFIX}");
            let _ = queue!(stdout, ResetColor);
            self.active_message = true;
        }
        let _ = write!(stdout, "{delta}");
        let _ = stdout.flush();
        self.delta_count += 1;
    }

    fn finish_message(&mut self) {
        if self.active_message {
            let mut stdout = std::io::stdout();
            let _ = writeln!(stdout);
            let _ = stdout.flush();
            self.active_message = false;
        }
    }
}

async fn display_agent_message_streamed(message: &str) {
    let message = message.trim();
    if message.is_empty() {
        return;
    }

    let mut stdout = std::io::stdout();
    let _ = queue!(
        stdout,
        SetForegroundColor(AGENT_PROMPT_COLOR),
        cursor::MoveToColumn(0)
    );
    let _ = write!(stdout, "{AGENT_PREFIX}");
    let _ = queue!(stdout, ResetColor);
    let _ = stdout.flush();

    for ch in message.chars() {
        let _ = write!(stdout, "{ch}");
        let _ = stdout.flush();
        tokio::task::yield_now().await;
    }

    let _ = writeln!(stdout);
    let _ = stdout.flush();
}

fn format_missing_decision_prompt(previous_response: &str) -> String {
    format!(
        r#"Your previous response did not follow the fallback tool protocol, so the runtime did not show it to the user.

Previous response:
{previous_response}

Return exactly one JSON object and no Markdown, no code fences, no extra text.
Use one of these shapes:
{{"action":"final","message":"polished Chinese answer for the user"}}
{{"action":"ask","message":"concise Chinese question for missing information"}}
{{"action":"call_tool","tool_name":"tool_name","input":{{...}}}}
"#
    )
}

async fn dispatch_with_progress(
    registry: &ToolRegistry,
    call: ToolCall,
) -> anyhow::Result<crate::tools::ToolOutput> {
    let render_state = Arc::new(Mutex::new(ProgressRenderState::default()));
    let progress = Arc::new(move |progress: crate::tools::ToolProgress| {
        if let Ok(mut state) = render_state.lock() {
            render_tool_progress(&progress, &mut state);
        }
    });

    registry
        .dispatch_with_progress(call, progress)
        .await
        .map_err(Into::into)
}

#[derive(Debug, Default)]
struct ProgressRenderState {
    block_lines: usize,
}

fn render_tool_progress(progress: &crate::tools::ToolProgress, state: &mut ProgressRenderState) {
    if progress
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("display_type"))
        .and_then(Value::as_str)
        == Some("checklist")
    {
        if let Some(lines) = checklist_progress_lines(progress) {
            render_checklist_in_place(&lines, state);
            return;
        }
    }

    println!("{}", format_percent_progress_line(progress));
}

fn format_percent_progress_line(progress: &crate::tools::ToolProgress) -> String {
    format!(
        "{} 进度: {}% - {}",
        top_level_tool_display_name(&progress.tool_name),
        progress.percent,
        progress.message
    )
}

fn checklist_progress_lines(progress: &crate::tools::ToolProgress) -> Option<Vec<String>> {
    let checklist = progress.metadata.as_ref()?.get("checklist")?.as_array()?;
    let mut rows = Vec::new();

    for item in checklist {
        let label = item.get("label").and_then(Value::as_str)?;
        let checked = item
            .get("checked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let marker = if checked { "✓" } else { "○" };
        rows.push(format!("{marker} {label}"));
    }

    Some(checklist_box_lines(
        &rows,
        &top_level_tool_display_name(&progress.tool_name),
    ))
}

fn checklist_box_lines(rows: &[String], title: &str) -> Vec<String> {
    let content_width = rows
        .iter()
        .map(|row| UnicodeWidthStr::width(row.as_str()))
        .chain(std::iter::once(UnicodeWidthStr::width(title) + 2))
        .max()
        .unwrap_or(0);
    let border = "─".repeat(content_width + 2);
    let mut lines = Vec::with_capacity(rows.len() + 2);
    if title.is_empty() {
        lines.push(format!("┌{border}┐"));
    } else {
        let title = format!(" {title} ");
        let title_width = UnicodeWidthStr::width(title.as_str());
        let right_border = "─".repeat((content_width + 2).saturating_sub(title_width));
        lines.push(format!("┌{title}{right_border}┐"));
    }
    for row in rows {
        let padding =
            " ".repeat(content_width.saturating_sub(UnicodeWidthStr::width(row.as_str())));
        lines.push(format!("│ {row}{padding} │"));
    }
    lines.push(format!("└{border}┘"));
    lines
}

fn render_checklist_in_place(lines: &[String], state: &mut ProgressRenderState) {
    let mut stdout = std::io::stdout();
    if state.block_lines > 0 {
        let _ = queue!(stdout, cursor::MoveUp(state.block_lines as u16));
    }

    let line_count = state.block_lines.max(lines.len());
    for index in 0..line_count {
        let _ = queue!(
            stdout,
            cursor::MoveToColumn(0),
            terminal::Clear(ClearType::CurrentLine)
        );
        if let Some(line) = lines.get(index) {
            let _ = write!(stdout, "{line}");
        }
        if index + 1 < line_count {
            let _ = queue!(stdout, cursor::MoveDown(1));
        } else {
            let _ = writeln!(stdout);
        }
    }

    let _ = stdout.flush();
    state.block_lines = lines.len();
}

async fn render_ai_spinner_until<F>(future: F) -> anyhow::Result<String>
where
    F: Future<Output = anyhow::Result<String>>,
{
    render_spinner_until("thinking", future).await
}

async fn render_tool_spinner_until<F, T>(tool_name: &str, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let label = top_level_tool_display_name(tool_name);
    render_spinner_until(&label, future).await
}

async fn render_spinner_until<F, T>(label: &str, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let spinner = SpinnerHandle::start(label);
    let result = future.await;
    spinner.stop();
    result
}

#[derive(Clone, Debug)]
struct SpinnerHandle {
    active: Arc<AtomicBool>,
}

impl SpinnerHandle {
    fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let active = Arc::new(AtomicBool::new(true));
        let task_active = Arc::clone(&active);

        tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut interval = time::interval(Duration::from_millis(90));
            let mut index = 0usize;

            while task_active.load(Ordering::SeqCst) {
                render_spinner_frame(frames[index % frames.len()], &label);
                index += 1;
                interval.tick().await;
            }
        });

        Self { active }
    }

    fn stop(&self) {
        if self.active.swap(false, Ordering::SeqCst) {
            clear_spinner_line();
        }
    }
}

fn render_spinner_frame(frame: &str, label: &str) {
    let mut stdout = std::io::stdout();
    let _ = queue!(
        stdout,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine),
        SetForegroundColor(Color::Rgb {
            r: 255,
            g: 176,
            b: 0,
        })
    );
    let _ = write!(stdout, "{frame} {label}");
    let _ = queue!(stdout, ResetColor);
    let _ = stdout.flush();
}

fn top_level_tool_display_name(tool_name: &str) -> String {
    let mut parts = tool_name.split("__");
    if parts.next() == Some("mcp")
        && let Some(server_name) = parts.next()
        && !server_name.is_empty()
    {
        return server_name.to_owned();
    }

    tool_name.to_owned()
}

fn clear_spinner_line() {
    let mut stdout = std::io::stdout();
    let _ = queue!(
        stdout,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine),
        ResetColor
    );
    let _ = stdout.flush();
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
    remote_mcp: &RemoteMcpToolbox,
    active_skill_context: &str,
) -> Vec<ChatMessage> {
    let mut messages = vec![ChatMessage::system(format_agent_loop_system_prompt(
        tools,
        remote_mcp,
        active_skill_context,
    ))];
    messages.extend(history.iter().map(copy_message));
    messages.push(ChatMessage::user(prompt));
    messages
}

fn build_native_agent_messages(
    history: &[ChatMessage],
    prompt: &str,
    tools: &[ToolSpec],
    remote_mcp: &RemoteMcpToolbox,
    active_skill_context: &str,
) -> Vec<ChatMessage> {
    let mut messages = vec![ChatMessage::system(format_native_agent_loop_system_prompt(
        tools,
        remote_mcp,
        active_skill_context,
    ))];
    messages.extend(history.iter().map(copy_message));
    messages.push(ChatMessage::user(prompt));
    messages
}

fn format_native_agent_loop_system_prompt(
    tools: &[ToolSpec],
    remote_mcp: &RemoteMcpToolbox,
    active_skill_context: &str,
) -> String {
    let agent_loop_instructions = format!(
        r#"You are running inside a Codex-style agent loop with native tool calls.

The runtime provides tools through the model API. Do not describe tool calls in text. When a tool is useful, call the tool natively. When the task is complete, answer the user directly in Chinese. When required information is missing, ask one concise Chinese question.

Available tool names:
{}

Remote MCP status:
{}

Rules:
- Use conversation history to resolve follow-up answers. If the user first gave a URL and later says "1.get 2.date=2026-05-13", combine them yourself.
- Call tools only for authorized/local/defensive testing requests.
- Remote MCP tools are named like mcp__server__tool. Use them when they can inspect a target website, browse pages, fetch target context, or provide capabilities that local tools do not have.
- If chrome-devtools MCP tools are available, do not claim you cannot access localhost, 127.0.0.1, or a browser page. Call the relevant MCP browser tool first. Only report a connection problem after an MCP tool call returns that concrete error.
- Browser MCP observations are evidence. After navigate/snapshot/click returns enough page context to answer the user's security question, stop calling tools and return a final Chinese analysis. Do not keep browsing just because more links or buttons exist.
- Do not repeat the same tool call with the same input. If a previous tool result already contains the current page, URL, visible text, or error, use that observation instead of calling another tool.
- Keep MCP browsing focused: use the tools needed to complete the task, but do not browse aimlessly.
- If a tool needs required fields that are missing or ambiguous, ask a concise Chinese clarification question instead of guessing.
- Never call database_risk_scan with only a bare URL. It needs at least one testable input point: query params in the URL, query_params, JSON body fields, or injectable_fields. If the user gives only a bare URL, ask for HTTP method and actual params/body fields.
- For database_risk_scan on HTML/PHP forms or DVWA medium/high, use body_format "form" for POST form fields. If the vulnerable value is submitted on one page and rendered on another page, use url for the submission endpoint and verification_url for the page that displays the database-backed result.
- For database_risk_scan blind SQL injection validation, keep confirm_time_based enabled unless the user asks for the lightest possible scan. Confirmation alternates normal and delayed probes to reduce false positives and must not extract database data.
- For weak_session_id_scan, sample the endpoint that generates or refreshes the ID. If the user mentions DVWA Weak Session IDs, look for the generated Set-Cookie token, commonly dvwaSession, and use enough samples to detect counters, timestamps, md5(time), and duplicate IDs. Do not attempt session takeover.
- For xss_risk_scan, do not call it with only a bare URL. It needs at least one testable input point: query params in the URL, query_params, object body fields, or injectable_fields. Use browser/MCP observations first when field names or rendering context are unknown.
- After a tool result is provided, return a final Chinese analysis for the developer. Do not repeat full JSON.
- When analyzing any tool result, include the report's three required parts: sample coverage, attack types, and how to fix. If the structured result has sample_coverage, attack_types, or remediation fields, use them directly.
- For database_risk_scan, prefer GET when the user says get, include query params in the url when supplied, and avoid inventing params.
- For http_load_test, ask for method/body/headers when not clear before calling.
"#,
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        format_remote_mcp_status(remote_mcp)
    );

    format!(
        "{}\n\n{}{}",
        default_system_prompt(),
        agent_loop_instructions,
        format_active_skill_prompt_section(active_skill_context)
    )
}

fn format_agent_loop_system_prompt(
    tools: &[ToolSpec],
    remote_mcp: &RemoteMcpToolbox,
    active_skill_context: &str,
) -> String {
    let agent_loop_instructions = format!(
        r#"You are now running inside an agent loop. You can either answer normally, ask for missing information, or call exactly one local or remote MCP tool.

Available tools:
{}

Remote MCP status:
{}

Fallback decision protocol:
This provider does not expose reliable native tool calls, so return exactly one JSON object and no Markdown, no code fences, no extra text.
Use one of these shapes:
{{"action":"ask","message":"concise Chinese question for missing information"}}
{{"action":"call_tool","tool_name":"tool_name","input":{{...}}}}
{{"action":"final","message":"polished Chinese answer for the user"}}

Rules:
- Use conversation history to resolve follow-up answers. If the user first gave a URL and later says "1.get 2.date=2026-05-13", combine them yourself.
- Call tools only for authorized/local/defensive testing requests.
- Remote MCP tools are named like mcp__server__tool. Use them when they can inspect a target website, browse pages, fetch target context, or provide capabilities that local tools do not have.
- If chrome-devtools MCP tools are available, do not claim you cannot access localhost, 127.0.0.1, or a browser page. Call the relevant MCP browser tool first. Only report a connection problem after an MCP tool call returns that concrete error.
- Browser MCP observations are evidence. After navigate/snapshot/click returns enough page context to answer the user's security question, stop calling tools and return a final Chinese analysis. Do not keep browsing just because more links or buttons exist.
- Do not repeat the same tool call with the same input. If a previous tool result already contains the current page, URL, visible text, or error, use that observation instead of calling another tool.
- Keep MCP browsing focused: use the tools needed to complete the task, but do not browse aimlessly.
- If a tool needs required fields that are missing or ambiguous, ask a concise Chinese clarification question instead of guessing.
- Final and ask decisions are shown to the user exactly once. Put the complete user-facing text in the message field.
- Never call database_risk_scan with only a bare URL. It needs at least one testable input point: query params in the URL, query_params, JSON body fields, or injectable_fields. If the user gives only a bare URL, ask for HTTP method and actual params/body fields.
- For database_risk_scan on HTML/PHP forms or DVWA medium/high, use body_format "form" for POST form fields. If the vulnerable value is submitted on one page and rendered on another page, use url for the submission endpoint and verification_url for the page that displays the database-backed result.
- For database_risk_scan blind SQL injection validation, keep confirm_time_based enabled unless the user asks for the lightest possible scan. Confirmation alternates normal and delayed probes to reduce false positives and must not extract database data.
- For weak_session_id_scan, sample the endpoint that generates or refreshes the ID. If the user mentions DVWA Weak Session IDs, look for the generated Set-Cookie token, commonly dvwaSession, and use enough samples to detect counters, timestamps, md5(time), and duplicate IDs. Do not attempt session takeover.
- For xss_risk_scan, do not call it with only a bare URL. It needs at least one testable input point: query params in the URL, query_params, object body fields, or injectable_fields. Use browser/MCP observations first when field names or rendering context are unknown.
- After a tool result is provided, return a final Chinese analysis for the developer. Do not repeat full JSON.
- When analyzing any tool result, include the report's three required parts: sample coverage, attack types, and how to fix. If the structured result has sample_coverage, attack_types, or remediation fields, use them directly.
- For database_risk_scan, prefer GET when the user says get, include query params in the url when supplied, and avoid inventing params.
- For http_load_test, ask for method/body/headers when not clear before calling.
"#,
        format_tools_for_agent(tools),
        format_remote_mcp_status(remote_mcp)
    );

    format!(
        "{}\n\n{}{}",
        default_system_prompt(),
        agent_loop_instructions,
        format_active_skill_prompt_section(active_skill_context)
    )
}

fn format_active_skill_prompt_section(active_skill_context: &str) -> String {
    if active_skill_context.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n# Runtime Skill Instructions\n\nThe following skill instructions are active for this user request. Follow them when they are more specific than the general workflow.\n\n{}",
            active_skill_context.trim()
        )
    }
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

fn format_remote_mcp_status(remote_mcp: &RemoteMcpToolbox) -> String {
    if remote_mcp.connection_errors().is_empty() {
        if remote_mcp.is_configured() {
            "Remote MCP tools are connected and included in Available tools.".to_owned()
        } else {
            "No remote MCP servers are configured.".to_owned()
        }
    } else {
        format!(
            "Some remote MCP servers are unavailable:\n{}",
            remote_mcp.connection_errors().join("\n")
        )
    }
}

fn parse_agent_decision(raw: &str) -> Option<AgentDecision> {
    serde_json::from_str::<AgentDecision>(raw.trim())
        .ok()
        .or_else(|| {
            extract_json_objects(raw)
                .into_iter()
                .find_map(|json| serde_json::from_str(&json).ok())
        })
}

fn extract_json_objects(raw: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let mut start = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if in_string {
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth += 1;
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start_index) = start.take() {
                        objects.push(raw[start_index..=index].to_owned());
                    }
                }
            }
            _ => {}
        }
    }

    objects
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

    let on_delta: CompletionDeltaCallback = Arc::new(|_| {});
    let response = client.complete_streaming(request, on_delta).await?;
    Ok(response.content)
}

async fn complete_with_thinking(
    client: &dyn LlmClient,
    messages: &[ChatMessage],
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<String> {
    render_ai_spinner_until(complete(client, messages, temperature, max_tokens)).await
}

async fn complete_with_thinking_retrying_temperature(
    client: &dyn LlmClient,
    messages: &[ChatMessage],
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> anyhow::Result<String> {
    let result = complete_with_thinking(client, messages, temperature, max_tokens).await;
    match result {
        Err(error)
            if temperature.is_some()
                && error
                    .downcast_ref::<crate::llm::LlmError>()
                    .is_some_and(|llm_error| {
                        client.should_retry_without_temperature(llm_error)
                    }) =>
        {
            complete_with_thinking(client, messages, None, max_tokens).await
        }
        other => other,
    }
}

async fn complete_agent_turn_retrying_temperature(
    client: &dyn LlmClient,
    request: AgentTurnRequest,
    on_delta: CompletionDeltaCallback,
) -> anyhow::Result<AgentTurnResponse> {
    let result = client
        .complete_agent_turn(request.clone(), Arc::clone(&on_delta))
        .await;
    match result {
        Err(error)
            if request.temperature.is_some() && client.should_retry_without_temperature(&error) =>
        {
            let mut retry_request = request;
            retry_request.temperature = None;
            Ok(client.complete_agent_turn(retry_request, on_delta).await?)
        }
        other => Ok(other?),
    }
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

        assert_eq!(names, vec!["/help", "/compact", "/clear", "/mcp", "/exit"]);
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
    fn parses_json_agent_tool_call_decision() {
        let decision = parse_agent_decision(
            r#"{"action":"call_tool","tool_name":"database_risk_scan","input":{"url":"https://target.example/api/search?date=2026-05-13","method":"GET"}}"#,
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
    fn parses_json_final_decision() {
        let decision = parse_agent_decision(
            r#"{"action":"final","message":"你好，我是 Safety Protection Agent。"}"#,
        )
        .expect("final decision should parse");

        match decision {
            AgentDecision::Final { message } => {
                assert_eq!(message, "你好，我是 Safety Protection Agent。");
            }
            _ => panic!("expected final"),
        }
    }

    #[test]
    fn parses_json_ask_inside_text() {
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
    fn parses_agent_decision_when_model_leaks_text_and_repeats_json() {
        let raw = r#"{"action":"call_tool","tool_name":"mcp__chrome-devtools__new_page","input":{"url":"https://lab.example/vulnerable/open_redirect/","timeout":5000}}
_HANDLE tool result? Actually must return JSON only. Since we call tool, final content is call_tool JSON.{"action":"call_tool","tool_name":"mcp__chrome-devtools__new_page","input":{"url":"https://lab.example/vulnerable/open_redirect/","timeout":5000}}"#;

        let decision = parse_agent_decision(raw).expect("decision should parse despite extra text");

        match decision {
            AgentDecision::CallTool { tool_name, input } => {
                assert_eq!(tool_name, "mcp__chrome-devtools__new_page");
                assert_eq!(
                    input["url"],
                    "https://lab.example/vulnerable/open_redirect/"
                );
            }
            _ => panic!("expected tool call"),
        }
    }

    #[test]
    fn missing_decision_prompt_requires_json_fallback_protocol() {
        let prompt = format_missing_decision_prompt("扫描结果看起来没问题。");

        assert!(prompt.contains("\"action\":\"final\""));
        assert!(prompt.contains("\"action\":\"ask\""));
        assert!(prompt.contains("\"action\":\"call_tool\""));
        assert!(prompt.contains("扫描结果看起来没问题。"));
    }

    #[test]
    fn percent_progress_line_shows_top_level_tool_name() {
        let progress =
            crate::tools::ToolProgress::new("http_load_test", "30/100 requests completed", 30, 100);

        let line = format_percent_progress_line(&progress);

        assert!(line.contains("http_load_test"));
        assert!(line.contains("30%"));
        assert!(line.contains("30/100 requests completed"));
        assert!(!line.contains("Tool progress"));
    }

    #[test]
    fn top_level_tool_display_name_hides_mcp_tool_detail() {
        assert_eq!(
            top_level_tool_display_name("mcp__chrome-devtools__click"),
            "chrome-devtools"
        );
        assert_eq!(
            top_level_tool_display_name("weak_session_id_scan"),
            "weak_session_id_scan"
        );
    }

    #[test]
    fn repl_prompt_labels_user_input() {
        assert_eq!(USER_PROMPT, "user> ");
        assert_eq!(AGENT_PREFIX, "agent> ");
    }

    #[test]
    fn eager_mcp_connect_only_for_explicit_browser_intent() {
        assert!(should_eager_connect_mcp(
            "直接使用mcp看chrome，账密是默认账密"
        ));
        assert!(should_eager_connect_mcp("用浏览器打开这个靶场"));
        assert!(should_eager_connect_mcp("inspect with DevTools"));
        assert!(!should_eager_connect_mcp("你好"));
        assert!(!should_eager_connect_mcp(
            "帮我分析这个接口有没有数据库漏洞"
        ));
    }

    #[test]
    fn parses_runtime_skill_frontmatter_and_body() {
        let raw = r#"---
name: web-vulnerability-discovery
description: Use for website vulnerability discovery.
---

# Web Vulnerability Discovery

Follow the evidence loop.
"#;

        let skill = parse_runtime_skill(raw).expect("skill should parse");

        assert_eq!(skill.name, "web-vulnerability-discovery");
        assert_eq!(
            skill.description,
            "Use for website vulnerability discovery."
        );
        assert!(skill.body.contains("Follow the evidence loop."));
    }

    #[test]
    fn parses_runtime_skill_frontmatter_as_yaml() {
        let raw = r#"---
name: web-vulnerability-discovery
description: "Use when a URL includes https://target.example:8443/path."
---

Body can contain frontmatter-looking separators.

---
"#;

        let skill = parse_runtime_skill(raw).expect("skill should parse");

        assert_eq!(skill.name, "web-vulnerability-discovery");
        assert_eq!(
            skill.description,
            "Use when a URL includes https://target.example:8443/path."
        );
        assert!(skill.body.contains("frontmatter-looking separators"));
    }

    #[test]
    fn ignores_runtime_skill_frontmatter_fields_outside_trigger_contract() {
        let raw = r#"---
name: web-vulnerability-discovery
description: Use for website vulnerability discovery.
metadata:
  short-description: Extra fields belong in agents/openai.yaml.
---

# Web Vulnerability Discovery
"#;

        let skill = parse_runtime_skill(raw).expect("skill should parse");

        assert_eq!(skill.name, "web-vulnerability-discovery");
        assert_eq!(
            skill.description,
            "Use for website vulnerability discovery."
        );
    }

    #[test]
    fn rejects_runtime_skill_with_invalid_name() {
        let raw = r#"---
name: Web Vulnerability Discovery
description: Use for website vulnerability discovery.
---

# Web Vulnerability Discovery
"#;

        assert!(parse_runtime_skill(raw).is_none());
    }

    #[test]
    fn web_vulnerability_skill_matches_chinese_site_request() {
        let skill = RuntimeSkill {
            name: "web-vulnerability-discovery".to_owned(),
            description: "Guide authorized website vulnerability discovery.".to_owned(),
            body: "body".to_owned(),
        };

        assert!(runtime_skill_matches(
            "帮我看看这个网站 https://target.example 有没有漏洞",
            &skill
        ));
        assert!(!runtime_skill_matches("你好，介绍一下你自己", &skill));
    }

    #[test]
    fn active_skill_context_is_added_to_agent_prompt() {
        let skill_context = format_active_skill_context(&[RuntimeSkill {
            name: "web-vulnerability-discovery".to_owned(),
            description: "Guide authorized website vulnerability discovery.".to_owned(),
            body: "Use MCP browser observations first.".to_owned(),
        }]);
        let prompt =
            format_agent_loop_system_prompt(&[], &RemoteMcpToolbox::empty(), &skill_context);

        assert!(prompt.contains("# Runtime Skill Instructions"));
        assert!(prompt.contains("$web-vulnerability-discovery"));
        assert!(prompt.contains("Use MCP browser observations first."));
    }

    #[test]
    fn agent_prompt_includes_tool_schemas_and_followup_rule() {
        let tools = vec![ToolSpec::new(
            "database_risk_scan",
            "Probe database risk.",
            json!({"type":"object","required":["url"]}),
        )];
        let prompt = format_agent_loop_system_prompt(&tools, &RemoteMcpToolbox::empty(), "");

        assert!(prompt.contains("database_risk_scan"));
        assert!(prompt.contains("1.get 2.date=2026-05-13"));
        assert!(prompt.contains("\"action\":\"call_tool\""));
        assert!(prompt.contains("Remote MCP status"));
        assert!(prompt.contains("body_format \"form\""));
        assert!(prompt.contains("verification_url"));
        assert!(prompt.contains("confirm_time_based"));
        assert!(prompt.contains("weak_session_id_scan"));
        assert!(prompt.contains("xss_risk_scan"));
        assert!(prompt.contains("dvwaSession"));
        assert!(prompt.contains("sample_coverage"));
        assert!(prompt.contains("attack_types"));
        assert!(prompt.contains("remediation"));
    }

    #[test]
    fn native_prompt_uses_native_tools_without_sentinel_protocol() {
        let tools = vec![ToolSpec::new(
            "database_risk_scan",
            "Probe database risk.",
            json!({"type":"object","required":["url"]}),
        )];
        let prompt = format_native_agent_loop_system_prompt(&tools, &RemoteMcpToolbox::empty(), "");

        assert!(prompt.contains("native tool calls"));
        assert!(prompt.contains("database_risk_scan"));
        assert!(!prompt.contains("SPA_DONE"));
        assert!(!prompt.contains("\"action\":\"call_tool\""));
    }
}
