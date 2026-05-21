use serde_json::Value;

#[derive(Debug, Clone)]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

impl ChatRole {
    pub(crate) fn as_openai_role(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }

    pub(crate) fn as_anthropic_role(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl CompletionRequest {
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            temperature: None,
            max_tokens: None,
        }
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
}

#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<ChatUsage>,
}

#[derive(Debug, Clone)]
pub struct ChatUsage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AgentToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

impl AgentToolSpec {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentTurnRequest {
    pub messages: Vec<ChatMessage>,
    pub input_items: Vec<AgentToolTranscriptItem>,
    pub tools: Vec<AgentToolSpec>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl AgentTurnRequest {
    pub fn new(messages: Vec<ChatMessage>, tools: Vec<AgentToolSpec>) -> Self {
        Self {
            messages,
            input_items: Vec::new(),
            tools,
            temperature: None,
            max_tokens: None,
        }
    }

    pub fn with_input_items(mut self, input_items: Vec<AgentToolTranscriptItem>) -> Self {
        self.input_items = input_items;
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentToolCall {
    pub id: String,
    pub call_id: String,
    pub name: String,
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentToolTranscriptItem {
    ToolCall {
        call_id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        call_id: String,
        output: String,
    },
}

impl AgentToolTranscriptItem {
    pub fn tool_call(tool_call: &AgentToolCall) -> Self {
        Self::ToolCall {
            call_id: tool_call.call_id.clone(),
            name: tool_call.name.clone(),
            input: tool_call.input.clone(),
        }
    }

    pub fn tool_result(call_id: impl Into<String>, output: impl Into<String>) -> Self {
        Self::ToolResult {
            call_id: call_id.into(),
            output: output.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentTurnResponse {
    pub content: String,
    pub tool_calls: Vec<AgentToolCall>,
    pub output_items: Vec<AgentToolTranscriptItem>,
    pub model: String,
    pub usage: Option<ChatUsage>,
}
