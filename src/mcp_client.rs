use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, Content};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{ToolOutput, ToolSpec};

const ENV_MCP_SERVERS: &str = "SPA_MCP_SERVERS";
const ENV_MCP_NAME: &str = "SPA_MCP_NAME";
const ENV_MCP_URL: &str = "SPA_MCP_URL";
const ENV_MCP_AUTH_TOKEN: &str = "SPA_MCP_AUTH_TOKEN";
const ENV_SPA_HOME: &str = "SPA_HOME";
const CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RemoteMcpServerConfig {
    pub name: String,
    #[serde(default = "default_mcp_transport")]
    pub transport: RemoteMcpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteMcpTransport {
    StreamableHttp,
    Stdio,
}

impl Default for RemoteMcpTransport {
    fn default() -> Self {
        Self::StreamableHttp
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SpaConfig {
    #[serde(default)]
    pub mcp_servers: HashMap<String, PersistedMcpServerConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PersistedMcpServerConfig {
    #[serde(default = "default_mcp_transport")]
    pub transport: RemoteMcpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

#[derive(Debug)]
pub struct RemoteMcpToolbox {
    servers: Vec<RemoteMcpServer>,
    tools: HashMap<String, RemoteToolRef>,
    connection_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMcpToolInfo {
    pub exposed_name: String,
    pub server_name: String,
    pub remote_name: String,
    pub description: Option<String>,
}

#[derive(Debug)]
struct RemoteMcpServer {
    client: RemoteMcpClient,
}

#[derive(Debug)]
enum RemoteMcpClient {
    Http(RunningService<RoleClient, ()>),
    Stdio(Mutex<StdioMcpClient>),
}

#[derive(Debug)]
struct StdioMcpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

#[derive(Debug, Clone)]
struct DiscoveredMcpTool {
    name: String,
    description: Option<String>,
    input_schema: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone)]
struct RemoteToolRef {
    server_index: usize,
    server_name: String,
    remote_name: String,
    spec: ToolSpec,
}

impl RemoteMcpToolbox {
    pub fn empty() -> Self {
        Self {
            servers: Vec::new(),
            tools: HashMap::new(),
            connection_errors: Vec::new(),
        }
    }

    pub fn with_connection_error(error: impl Into<String>) -> Self {
        Self {
            servers: Vec::new(),
            tools: HashMap::new(),
            connection_errors: vec![error.into()],
        }
    }

    pub async fn from_env() -> anyhow::Result<Self> {
        let configs = load_remote_mcp_configs()?;
        Self::connect(configs).await
    }

    pub async fn connect(configs: Vec<RemoteMcpServerConfig>) -> anyhow::Result<Self> {
        let mut servers = Vec::new();
        let mut tools = HashMap::new();
        let mut connection_errors = Vec::new();

        for config in configs {
            let server_name = sanitize_server_name(&config.name);
            if server_name.is_empty() {
                connection_errors.push(format!(
                    "MCP server `{}` was skipped because its sanitized name is empty.",
                    config.name
                ));
                continue;
            }

            match connect_server(&config).await {
                Ok((server, remote_tools)) => {
                    let server_index = servers.len();
                    for tool in remote_tools {
                        let remote_name = tool.name;
                        let exposed_name = exposed_tool_name(&server_name, &remote_name);
                        let spec = ToolSpec::new(
                            exposed_name.clone(),
                            format!(
                                "[MCP:{}] {}",
                                server_name,
                                tool.description.as_deref().unwrap_or("Remote MCP tool.")
                            ),
                            Value::Object(tool.input_schema),
                        );
                        tools.insert(
                            exposed_name,
                            RemoteToolRef {
                                server_index,
                                server_name: server_name.clone(),
                                remote_name,
                                spec,
                            },
                        );
                    }
                    servers.push(server);
                }
                Err(error) => {
                    connection_errors.push(format!(
                        "MCP server `{}` failed to connect: {error}",
                        config.name
                    ));
                }
            }
        }

        Ok(Self {
            servers,
            tools,
            connection_errors,
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.servers.is_empty() || !self.connection_errors.is_empty()
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        let mut specs: Vec<_> = self
            .tools
            .values()
            .map(|remote_tool| remote_tool.spec.clone())
            .collect();
        specs.sort_by(|left, right| left.name.cmp(&right.name));
        specs
    }

    pub fn tool_infos(&self) -> Vec<RemoteMcpToolInfo> {
        let mut infos: Vec<_> = self
            .tools
            .iter()
            .map(|(exposed_name, remote_tool)| RemoteMcpToolInfo {
                exposed_name: exposed_name.clone(),
                server_name: remote_tool.server_name.clone(),
                remote_name: remote_tool.remote_name.clone(),
                description: Some(remote_tool.spec.description.clone()),
            })
            .collect();
        infos.sort_by(|left, right| left.exposed_name.cmp(&right.exposed_name));
        infos
    }

    pub fn has(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    pub fn connection_errors(&self) -> &[String] {
        &self.connection_errors
    }

    pub async fn call(&self, name: &str, input: Value) -> anyhow::Result<ToolOutput> {
        let tool_ref = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown remote MCP tool: {name}"))?;
        let result = self.servers[tool_ref.server_index]
            .client
            .call_tool(tool_ref.remote_name.clone(), input)
            .await?;

        Ok(call_tool_result_to_output(name, result))
    }

    pub async fn shutdown(self) {
        for server in self.servers {
            server.client.shutdown().await;
        }
    }
}

impl RemoteMcpClient {
    async fn call_tool(&self, name: String, input: Value) -> anyhow::Result<CallToolResult> {
        match self {
            RemoteMcpClient::Http(client) => {
                let arguments = match input {
                    Value::Object(object) => Some(object),
                    Value::Null => None,
                    value => {
                        return Err(anyhow::anyhow!(
                            "remote MCP tool `{name}` expects an object input, got {value}"
                        ));
                    }
                };
                let params = CallToolRequestParams {
                    meta: None,
                    name: name.into(),
                    arguments,
                    task: None,
                };
                Ok(client.peer().call_tool(params).await?)
            }
            RemoteMcpClient::Stdio(client) => {
                let mut client = client
                    .lock()
                    .map_err(|_| anyhow::anyhow!("stdio MCP client lock poisoned"))?;
                client.call_tool(&name, input)
            }
        }
    }

    async fn shutdown(self) {
        match self {
            RemoteMcpClient::Http(client) => {
                let _ = client.cancel().await;
            }
            RemoteMcpClient::Stdio(client) => {
                if let Ok(mut client) = client.into_inner() {
                    kill_child_process_tree(&mut client.child);
                    let _ = client.child.wait();
                }
            }
        }
    }
}

fn kill_child_process_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    let _ = child.kill();
}

async fn connect_server(
    config: &RemoteMcpServerConfig,
) -> anyhow::Result<(RemoteMcpServer, Vec<DiscoveredMcpTool>)> {
    match config.transport {
        RemoteMcpTransport::StreamableHttp => {
            let url = config
                .url
                .as_ref()
                .filter(|url| !url.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("streamable-http MCP server requires url"))?;
            let transport =
                if let Some(token) = config.auth_token.as_ref().filter(|token| !token.is_empty()) {
                    StreamableHttpClientTransport::from_config(
                        StreamableHttpClientTransportConfig::with_uri(url.clone())
                            .auth_header(token.clone()),
                    )
                } else {
                    StreamableHttpClientTransport::from_uri(url.clone())
                };
            let client = ().serve(transport).await?;
            let tools = client
                .peer()
                .list_all_tools()
                .await?
                .into_iter()
                .map(|tool| DiscoveredMcpTool {
                    name: tool.name.to_string(),
                    description: tool.description.map(|description| description.to_string()),
                    input_schema: (*tool.input_schema).clone(),
                })
                .collect();
            Ok((
                RemoteMcpServer {
                    client: RemoteMcpClient::Http(client),
                },
                tools,
            ))
        }
        RemoteMcpTransport::Stdio => {
            let command = config
                .command
                .as_ref()
                .filter(|command| !command.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("stdio MCP server requires command"))?;
            let mut client = StdioMcpClient::spawn(command, &config.args)?;
            let tools = client.initialize_and_list_tools()?;
            Ok((
                RemoteMcpServer {
                    client: RemoteMcpClient::Stdio(Mutex::new(client)),
                },
                tools,
            ))
        }
    }
}

impl StdioMcpClient {
    fn spawn(command: &str, args: &[String]) -> anyhow::Result<Self> {
        let resolved_command = resolve_stdio_command(command);
        let mut child = Command::new(&resolved_command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to spawn `{}` resolved from `{command}`: {error}",
                    resolved_command.display()
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open MCP child stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open MCP child stdout"))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn initialize_and_list_tools(&mut self) -> anyhow::Result<Vec<DiscoveredMcpTool>> {
        self.request(json!({
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "safety-protection-agent",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }))?;
        self.notify(json!({
            "method": "notifications/initialized",
            "params": {}
        }))?;

        let result = self.request(json!({
            "method": "tools/list",
            "params": {}
        }))?;
        parse_stdio_tools(result)
    }

    fn call_tool(&mut self, name: &str, input: Value) -> anyhow::Result<CallToolResult> {
        let arguments = match input {
            Value::Object(object) => Value::Object(object),
            Value::Null => json!({}),
            value => {
                return Err(anyhow::anyhow!(
                    "remote MCP tool `{name}` expects an object input, got {value}"
                ));
            }
        };
        let result = self.request(json!({
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))?;

        serde_json::from_value(result)
            .map_err(|error| anyhow::anyhow!("invalid MCP tools/call result: {error}"))
    }

    fn notify(&mut self, mut message: Value) -> anyhow::Result<()> {
        message["jsonrpc"] = Value::String("2.0".to_owned());
        let line = serde_json::to_string(&message)?;
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn request(&mut self, mut message: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        message["jsonrpc"] = Value::String("2.0".to_owned());
        message["id"] = Value::from(id);
        let line = serde_json::to_string(&message)?;
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;

        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line)?;
            if read == 0 {
                anyhow::bail!("MCP stdio server closed stdout");
            }
            let response: Value = match serde_json::from_str(line.trim()) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = response.get("error") {
                anyhow::bail!("MCP JSON-RPC error: {error}");
            }
            return Ok(response.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

fn resolve_stdio_command(command: &str) -> PathBuf {
    let command_path = PathBuf::from(command);
    if command_path.components().count() > 1 || command_path.extension().is_some() {
        return command_path;
    }

    #[cfg(windows)]
    {
        let path_exts = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .split(';')
            .filter(|ext| !ext.trim().is_empty())
            .map(|ext| ext.trim().to_owned())
            .collect::<Vec<_>>();

        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                for ext in &path_exts {
                    let candidate = dir.join(format!("{command}{ext}"));
                    if candidate.is_file() {
                        return candidate;
                    }
                }
                let direct = dir.join(command);
                if direct.is_file() {
                    return direct;
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let candidate = dir.join(command);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }

    command_path
}

fn parse_stdio_tools(result: Value) -> anyhow::Result<Vec<DiscoveredMcpTool>> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("MCP tools/list result missing tools array"))?;
    let mut parsed = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("MCP tool missing name"))?
            .to_owned();
        let description = tool
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let input_schema = tool
            .get("inputSchema")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| {
                let mut schema = serde_json::Map::new();
                schema.insert("type".to_owned(), Value::String("object".to_owned()));
                schema
            });
        parsed.push(DiscoveredMcpTool {
            name,
            description,
            input_schema,
        });
    }

    Ok(parsed)
}

fn call_tool_result_to_output(tool_name: &str, result: CallToolResult) -> ToolOutput {
    let content = content_to_text(&result.content);
    let mut metadata = json!({
        "source": "mcp",
        "is_error": result.is_error.unwrap_or(false),
    });

    if let Some(structured_content) = result.structured_content {
        metadata["structured_content"] = structured_content;
    }

    ToolOutput::text(tool_name.to_owned(), content).with_metadata(metadata)
}

fn content_to_text(contents: &[Content]) -> String {
    let parts: Vec<String> = contents
        .iter()
        .map(|content| {
            content
                .as_text()
                .map(|text| text.text.clone())
                .unwrap_or_else(|| {
                    serde_json::to_string(content)
                        .unwrap_or_else(|_| "<non-text MCP content>".to_owned())
                })
        })
        .collect();

    parts.join("\n")
}

pub fn load_remote_mcp_configs() -> anyhow::Result<Vec<RemoteMcpServerConfig>> {
    let mut configs = load_remote_mcp_configs_from_file()?;
    configs.extend(load_remote_mcp_configs_from_env()?);
    Ok(configs)
}

pub fn load_remote_mcp_configs_from_file() -> anyhow::Result<Vec<RemoteMcpServerConfig>> {
    let path = spa_config_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    let config = parse_spa_config_toml(&raw)
        .map_err(|error| anyhow::anyhow!("invalid {}: {error}", path.display()))?;

    Ok(config
        .mcp_servers
        .into_iter()
        .map(|(name, server)| RemoteMcpServerConfig {
            name,
            transport: server.transport,
            url: server.url,
            auth_token: server.auth_token,
            command: server.command,
            args: server.args,
        })
        .collect())
}

pub fn add_stdio_mcp_server(name: &str, command: &[String]) -> anyhow::Result<PathBuf> {
    if sanitize_identifier(name) != name {
        anyhow::bail!(
            "invalid MCP server name `{name}`; use only ASCII letters, numbers, '-' or '_'"
        );
    }
    if command.is_empty() {
        anyhow::bail!("mcp add requires a command after --");
    }

    let path = spa_config_path();
    let mut config = load_spa_config_from_path(&path)?;
    config.mcp_servers.insert(
        name.to_owned(),
        PersistedMcpServerConfig {
            transport: RemoteMcpTransport::Stdio,
            url: None,
            auth_token: None,
            command: Some(command[0].to_owned()),
            args: command[1..].to_vec(),
        },
    );
    save_spa_config_to_path(&path, &config)?;
    Ok(path)
}

pub fn load_spa_config_from_path(path: &std::path::Path) -> anyhow::Result<SpaConfig> {
    if !path.exists() {
        return Ok(SpaConfig::default());
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    parse_spa_config_toml(&raw)
        .map_err(|error| anyhow::anyhow!("invalid {}: {error}", path.display()))
}

pub fn save_spa_config_to_path(path: &std::path::Path, config: &SpaConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("failed to create {}: {error}", parent.display()))?;
    }
    let raw = format_spa_config_toml(config);
    std::fs::write(path, raw)
        .map_err(|error| anyhow::anyhow!("failed to write {}: {error}", path.display()))?;
    Ok(())
}

fn format_spa_config_toml(config: &SpaConfig) -> String {
    let mut names: Vec<_> = config.mcp_servers.keys().collect();
    names.sort();

    let mut output = String::new();
    for name in names {
        let server = &config.mcp_servers[name];
        output.push_str(&format!("[mcp_servers.{}]\n", quote_key_if_needed(name)));
        output.push_str(&format!(
            "transport = \"{}\"\n",
            match server.transport {
                RemoteMcpTransport::StreamableHttp => "streamable-http",
                RemoteMcpTransport::Stdio => "stdio",
            }
        ));
        if let Some(url) = &server.url {
            output.push_str(&format!("url = \"{}\"\n", escape_toml_string(url)));
        }
        if let Some(auth_token) = &server.auth_token {
            output.push_str(&format!(
                "auth_token = \"{}\"\n",
                escape_toml_string(auth_token)
            ));
        }
        if let Some(command) = &server.command {
            output.push_str(&format!("command = \"{}\"\n", escape_toml_string(command)));
        }
        if !server.args.is_empty() {
            let args = server
                .args
                .iter()
                .map(|arg| format!("\"{}\"", escape_toml_string(arg)))
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!("args = [{args}]\n"));
        }
        output.push('\n');
    }

    output
}

fn parse_spa_config_toml(raw: &str) -> anyhow::Result<SpaConfig> {
    let mut config = SpaConfig::default();
    let mut current_name: Option<String> = None;

    for (line_index, raw_line) in raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            let Some(name) = section.strip_prefix("mcp_servers.") else {
                anyhow::bail!("unsupported section `{section}` at line {}", line_index + 1);
            };
            let name = parse_toml_key(name)?;
            config.mcp_servers.entry(name.clone()).or_default();
            current_name = Some(name);
            continue;
        }

        let Some(name) = current_name.as_ref() else {
            anyhow::bail!("key outside mcp_servers section at line {}", line_index + 1);
        };
        let Some((key, value)) = line.split_once('=') else {
            anyhow::bail!("expected key = value at line {}", line_index + 1);
        };
        let key = key.trim();
        let value = value.trim();
        let server = config
            .mcp_servers
            .get_mut(name)
            .expect("current section should exist");

        match key {
            "transport" => {
                server.transport = match parse_toml_string(value)?.as_str() {
                    "streamable-http" => RemoteMcpTransport::StreamableHttp,
                    "stdio" => RemoteMcpTransport::Stdio,
                    other => anyhow::bail!("unsupported MCP transport `{other}`"),
                };
            }
            "url" => server.url = Some(parse_toml_string(value)?),
            "auth_token" => server.auth_token = Some(parse_toml_string(value)?),
            "command" => server.command = Some(parse_toml_string(value)?),
            "args" => server.args = parse_toml_string_array(value)?,
            other => anyhow::bail!("unsupported MCP config key `{other}`"),
        }
    }

    Ok(config)
}

fn quote_key_if_needed(key: &str) -> String {
    if key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        key.to_owned()
    } else {
        format!("\"{}\"", escape_toml_string(key))
    }
}

fn parse_toml_key(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.starts_with('"') {
        parse_toml_string(value)
    } else {
        Ok(value.to_owned())
    }
}

fn parse_toml_string_array(value: &str) -> anyhow::Result<Vec<String>> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        anyhow::bail!("expected TOML string array");
    }
    let inner = value[1..value.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => {
                current.push(ch);
                in_string = !in_string;
            }
            ',' if !in_string => {
                values.push(parse_toml_string(current.trim())?);
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        values.push(parse_toml_string(current.trim())?);
    }
    Ok(values)
}

fn parse_toml_string(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        anyhow::bail!("expected TOML string");
    }
    let mut output = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            anyhow::bail!("unterminated TOML escape");
        };
        match escaped {
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            other => anyhow::bail!("unsupported TOML escape `\\{other}`"),
        }
    }
    Ok(output)
}

fn escape_toml_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

pub fn spa_config_path() -> PathBuf {
    spa_home().join(CONFIG_FILE_NAME)
}

fn spa_home() -> PathBuf {
    if let Ok(home) = std::env::var(ENV_SPA_HOME) {
        return PathBuf::from(home);
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        return PathBuf::from(home).join(".spa");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".spa");
    }
    PathBuf::from(".spa")
}

pub fn load_remote_mcp_configs_from_env() -> anyhow::Result<Vec<RemoteMcpServerConfig>> {
    if let Ok(raw) = std::env::var(ENV_MCP_SERVERS) {
        if raw.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut configs: Vec<RemoteMcpServerConfig> = serde_json::from_str(&raw)
            .map_err(|error| anyhow::anyhow!("invalid {ENV_MCP_SERVERS}: {error}"))?;
        for config in &mut configs {
            if config.transport == RemoteMcpTransport::StreamableHttp && config.url.is_none() {
                config.url = Some(String::new());
            }
        }
        return Ok(configs);
    }

    let Ok(url) = std::env::var(ENV_MCP_URL) else {
        return Ok(Vec::new());
    };
    if url.trim().is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![RemoteMcpServerConfig {
        name: std::env::var(ENV_MCP_NAME).unwrap_or_else(|_| "remote".to_owned()),
        transport: RemoteMcpTransport::StreamableHttp,
        url: Some(url),
        auth_token: std::env::var(ENV_MCP_AUTH_TOKEN).ok(),
        command: None,
        args: Vec::new(),
    }])
}

fn default_mcp_transport() -> RemoteMcpTransport {
    RemoteMcpTransport::StreamableHttp
}

fn exposed_tool_name(server_name: &str, tool_name: &str) -> String {
    format!("mcp__{}__{}", server_name, sanitize_tool_suffix(tool_name))
}

fn sanitize_server_name(name: &str) -> String {
    sanitize_identifier(name)
}

fn sanitize_tool_suffix(name: &str) -> String {
    sanitize_identifier(name)
}

fn sanitize_identifier(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn exposes_codex_style_mcp_tool_name() {
        assert_eq!(
            exposed_tool_name("browser", "open.page"),
            "mcp__browser__open_page"
        );
    }

    #[test]
    fn parses_single_server_from_env_url() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            std::env::remove_var(ENV_MCP_SERVERS);
            std::env::set_var(ENV_MCP_URL, "http://127.0.0.1:8000/mcp");
            std::env::set_var(ENV_MCP_NAME, "browser");
            std::env::remove_var(ENV_MCP_AUTH_TOKEN);
        }

        let configs = load_remote_mcp_configs_from_env().expect("config should parse");

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "browser");
        assert_eq!(configs[0].url.as_deref(), Some("http://127.0.0.1:8000/mcp"));

        unsafe {
            std::env::remove_var(ENV_MCP_URL);
            std::env::remove_var(ENV_MCP_NAME);
        }
    }

    #[test]
    fn parses_server_list_from_env_json() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            std::env::set_var(
                ENV_MCP_SERVERS,
                r#"[{"name":"browser","url":"http://127.0.0.1:8000/mcp","auth_token":"token"}]"#,
            );
            std::env::remove_var(ENV_MCP_URL);
        }

        let configs = load_remote_mcp_configs_from_env().expect("config should parse");

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].auth_token.as_deref(), Some("token"));

        unsafe {
            std::env::remove_var(ENV_MCP_SERVERS);
        }
    }

    #[test]
    fn adds_stdio_server_to_config_file() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        let home = std::env::temp_dir().join(format!("spa-test-{}", uuid::Uuid::new_v4()));
        unsafe {
            std::env::set_var(ENV_SPA_HOME, &home);
            std::env::remove_var(ENV_MCP_SERVERS);
            std::env::remove_var(ENV_MCP_URL);
        }

        let path = add_stdio_mcp_server(
            "chrome-devtools",
            &["npx".to_owned(), "chrome-devtools-mcp@latest".to_owned()],
        )
        .expect("mcp server should be saved");
        let config = load_spa_config_from_path(&path).expect("config should reload");
        let server = config
            .mcp_servers
            .get("chrome-devtools")
            .expect("server should exist");

        assert_eq!(server.transport, RemoteMcpTransport::Stdio);
        assert_eq!(server.command.as_deref(), Some("npx"));
        assert_eq!(server.args, vec!["chrome-devtools-mcp@latest"]);

        unsafe {
            std::env::remove_var(ENV_SPA_HOME);
        }
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn converts_mcp_result_to_tool_output() {
        let result = CallToolResult {
            content: vec![Content::text("ok")],
            structured_content: Some(json!({ "value": 1 })),
            is_error: Some(false),
            meta: None,
        };

        let output = call_tool_result_to_output("mcp__server__tool", result);

        assert_eq!(output.content, "ok");
        assert_eq!(
            output.metadata.unwrap()["structured_content"],
            json!({ "value": 1 })
        );
    }

    #[test]
    fn leaves_explicit_stdio_command_path_unchanged() {
        assert_eq!(
            resolve_stdio_command("C:\\tools\\npx.cmd"),
            PathBuf::from("C:\\tools\\npx.cmd")
        );
    }

    #[test]
    fn resolves_npx_to_executable_path() {
        let resolved = resolve_stdio_command("npx");

        if resolved != PathBuf::from("npx") {
            assert!(resolved.extension().is_some());
        }
    }
}
