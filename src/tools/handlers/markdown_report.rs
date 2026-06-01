use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::agent::config::AgentConfig;
use crate::tools::{Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolSpec};

#[derive(Debug, Clone, Copy)]
pub struct GenerateMarkdownReportTool;

#[async_trait]
impl ToolHandler for GenerateMarkdownReportTool {
    fn name(&self) -> &'static str {
        "generate_markdown_report"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Write a completed Markdown security report to SPA_AGENT_REPORT_DIR and return the file path. Use only when a completed report is ready; do not use for ordinary chat, clarifying questions, or drafts. Security reports must use the four Chinese risk labels 【高危】, 【危险】, 【警告】, and 【正常】 in attack coverage and findings.",
            json!({
                "type": "object",
                "properties": {
                    "report_name": {
                        "type": "string",
                        "description": "Human-readable report name used to derive the Markdown filename. Prefer a target-specific Chinese name."
                    },
                    "report_markdown": {
                        "type": "string",
                        "description": "Complete Markdown report content to write. Include the same final report that will be shown to the user. Every attack coverage result and finding risk level must contain one of 【高危】, 【危险】, 【警告】, or 【正常】."
                    }
                },
                "required": ["report_markdown"],
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        let input: GenerateMarkdownReportInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;
        let report_markdown = input.report_markdown.trim();
        if report_markdown.is_empty() {
            return Err(ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: "report_markdown must not be empty".to_owned(),
            });
        }

        let config = AgentConfig::from_env().map_err(|error| ToolError::Execution {
            tool: self.name().to_owned(),
            message: error.to_string(),
        })?;
        let path = config
            .write_markdown_report(report_markdown, input.report_name.as_deref())
            .map_err(|error| ToolError::Execution {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?
            .ok_or_else(|| ToolError::Execution {
                tool: self.name().to_owned(),
                message: "SPA_AGENT_REPORT_DIR is not configured".to_owned(),
            })?;
        let path_display = path.display().to_string();

        Ok(ToolOutput::text(
            call.id,
            format!("Markdown report written: {path_display}"),
        )
        .with_metadata(json!({
            "path": path_display,
            "file_name": path.file_name().and_then(|value| value.to_str()).unwrap_or_default()
        })))
    }
}

#[derive(Debug, Deserialize)]
struct GenerateMarkdownReportInput {
    #[serde(default)]
    report_name: Option<String>,
    report_markdown: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn writes_markdown_report_to_configured_dir() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        let root = std::env::temp_dir().join(format!("spa-report-tool-{}", uuid::Uuid::new_v4()));
        unsafe {
            std::env::set_var("SPA_AGENT_REPORT_DIR", &root);
        }

        let output = GenerateMarkdownReportTool
            .handle(ToolCall::new(
                "generate_markdown_report",
                json!({
                    "report_name": "自检报告",
                    "report_markdown": "报告名称：自检报告\n\n## 样本覆盖\n\n已检查。"
                }),
            ))
            .await
            .expect("report should write");

        unsafe {
            std::env::remove_var("SPA_AGENT_REPORT_DIR");
        }

        assert!(output.content.contains("Markdown report written"));
        let path = root.join("自检报告.md");
        assert!(path.is_file());
        let raw = fs::read_to_string(path).expect("report should be readable");
        assert!(raw.contains("报告名称：自检报告"));

        let _ = fs::remove_dir_all(root);
    }
}
