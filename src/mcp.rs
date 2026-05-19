use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientJsonRpcMessage, ClientNotification, ClientRequest,
    Content, ErrorCode, ErrorData, Implementation, InitializeResult, JsonObject,
    JsonRpcNotification, JsonRpcRequest, ListToolsResult, Notification, NumberOrString,
    ProgressNotificationParam, RequestId, RequestParamsMeta, ServerCapabilities,
    ServerJsonRpcMessage, ServerNotification, ServerResult, Tool, ToolsCapability,
};
use serde_json::{Value, json};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::tools::{ToolCall, ToolRegistry, ToolSpec};

const SERVER_NAME: &str = "safety-protection-agent-mcp";

pub async fn run_stdio() -> anyhow::Result<()> {
    let registry = ToolRegistry::with_builtins()?;
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = io::stdout();
    let mut initialized = false;

    while let Some(line) = lines.next_line().await? {
        let message = match serde_json::from_str::<ClientJsonRpcMessage>(&line) {
            Ok(message) => message,
            Err(error) => {
                send_error(
                    &mut stdout,
                    NumberOrString::Number(0),
                    ErrorData::invalid_request(
                        format!("failed to deserialize JSON-RPC message: {error}"),
                        None,
                    ),
                )
                .await?;
                continue;
            }
        };

        match message {
            ClientJsonRpcMessage::Request(request) => {
                process_request(&mut stdout, &registry, &mut initialized, request).await?;
            }
            ClientJsonRpcMessage::Notification(notification) => {
                process_notification(notification);
            }
            ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_) => {}
        }
    }

    Ok(())
}

async fn process_request(
    stdout: &mut io::Stdout,
    registry: &ToolRegistry,
    initialized: &mut bool,
    request: JsonRpcRequest<ClientRequest>,
) -> anyhow::Result<()> {
    let request_id = request.id.clone();
    match request.request {
        ClientRequest::InitializeRequest(params) => {
            if *initialized {
                send_error(
                    stdout,
                    request_id,
                    ErrorData::invalid_request("initialize called more than once", None),
                )
                .await?;
                return Ok(());
            }

            let server_info = Implementation {
                name: SERVER_NAME.to_owned(),
                title: Some("Safety Protection Agent".to_owned()),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                description: None,
                icons: None,
                website_url: None,
            };
            let result = InitializeResult {
                capabilities: ServerCapabilities {
                    tools: Some(ToolsCapability {
                        list_changed: Some(true),
                    }),
                    ..Default::default()
                },
                instructions: Some(
                    "Tools are defensive security and reliability probes. Ask for missing request details before calling tools."
                        .to_owned(),
                ),
                protocol_version: params.params.protocol_version,
                server_info,
            };
            *initialized = true;
            send_response(stdout, request_id, ServerResult::InitializeResult(result)).await?;
        }
        ClientRequest::PingRequest(_) => {
            send_response(stdout, request_id, ServerResult::empty(())).await?;
        }
        ClientRequest::ListToolsRequest(_) => {
            send_response(
                stdout,
                request_id,
                ServerResult::ListToolsResult(ListToolsResult {
                    meta: None,
                    tools: registry.specs().into_iter().map(tool_from_spec).collect(),
                    next_cursor: None,
                }),
            )
            .await?;
        }
        ClientRequest::CallToolRequest(params) => {
            handle_call_tool(stdout, registry, request_id, params.params).await?;
        }
        ClientRequest::CustomRequest(custom) => {
            send_error(
                stdout,
                request_id,
                ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    format!("method not found: {}", custom.method),
                    Some(json!({ "method": custom.method })),
                ),
            )
            .await?;
        }
        other => {
            send_error(
                stdout,
                request_id,
                ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    "method not implemented by spa-mcp",
                    Some(json!({ "request": format!("{other:?}") })),
                ),
            )
            .await?;
        }
    }

    Ok(())
}

fn process_notification(notification: JsonRpcNotification<ClientNotification>) {
    match notification.notification {
        ClientNotification::InitializedNotification(_) => {}
        ClientNotification::CancelledNotification(_)
        | ClientNotification::ProgressNotification(_)
        | ClientNotification::RootsListChangedNotification(_)
        | ClientNotification::CustomNotification(_) => {}
    }
}

async fn handle_call_tool(
    stdout: &mut io::Stdout,
    registry: &ToolRegistry,
    request_id: RequestId,
    params: CallToolRequestParams,
) -> anyhow::Result<()> {
    let name = params.name.to_string();
    let progress_token = params.progress_token();
    let input = params
        .arguments
        .map(Value::Object)
        .unwrap_or_else(|| json!({}));
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let progress = Arc::new(move |progress| {
        let _ = progress_tx.send(progress);
    });
    let dispatch = registry.dispatch_with_progress(
        ToolCall {
            id: request_id.to_string(),
            name: name.clone(),
            input,
        },
        progress,
    );
    tokio::pin!(dispatch);

    let result = loop {
        tokio::select! {
            Some(progress) = progress_rx.recv() => {
                if let Some(progress_token) = progress_token.clone() {
                    send_progress(stdout, progress_token, progress).await?;
                }
            }
            result = &mut dispatch => break result,
        }
    };

    match result {
        Ok(output) => {
            let result = CallToolResult {
                content: vec![Content::text(output.content)],
                structured_content: output.metadata,
                is_error: Some(false),
                meta: None,
            };
            send_response(stdout, request_id, ServerResult::CallToolResult(result)).await?;
        }
        Err(error) => {
            let result = CallToolResult {
                content: vec![Content::text(format!("{error}"))],
                structured_content: None,
                is_error: Some(true),
                meta: None,
            };
            send_response(stdout, request_id, ServerResult::CallToolResult(result)).await?;
        }
    }

    Ok(())
}

fn tool_from_spec(spec: ToolSpec) -> Tool {
    Tool {
        name: spec.name.into(),
        title: None,
        input_schema: Arc::new(json_object(spec.input_schema).unwrap_or_default()),
        output_schema: Some(Arc::new(output_schema())),
        description: Some(spec.description.into()),
        annotations: None,
        execution: None,
        icons: None,
        meta: None,
    }
}

fn output_schema() -> JsonObject {
    json_object(json!({
        "type": "object",
        "properties": {
            "content": { "type": "string" }
        },
        "required": ["content"]
    }))
    .unwrap_or_default()
}

fn json_object(value: Value) -> Option<JsonObject> {
    match value {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

async fn send_response(
    stdout: &mut io::Stdout,
    id: RequestId,
    response: ServerResult,
) -> anyhow::Result<()> {
    write_message(stdout, ServerJsonRpcMessage::response(response, id)).await
}

async fn send_error(
    stdout: &mut io::Stdout,
    id: RequestId,
    error: ErrorData,
) -> anyhow::Result<()> {
    write_message(stdout, ServerJsonRpcMessage::error(error, id)).await
}

async fn send_progress(
    stdout: &mut io::Stdout,
    progress_token: rmcp::model::ProgressToken,
    progress: crate::tools::ToolProgress,
) -> anyhow::Result<()> {
    let notification = ProgressNotificationParam {
        progress_token,
        progress: progress.completed_units as f64,
        total: (progress.total_units > 0).then_some(progress.total_units as f64),
        message: Some(progress.message),
    };
    write_message(
        stdout,
        ServerJsonRpcMessage::notification(ServerNotification::ProgressNotification(
            Notification::new(notification),
        )),
    )
    .await
}

async fn write_message(
    stdout: &mut io::Stdout,
    message: ServerJsonRpcMessage,
) -> anyhow::Result<()> {
    let line = serde_json::to_string(&message)?;
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}
