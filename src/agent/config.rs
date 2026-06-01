use std::fs;
use std::path::{Path, PathBuf};

const ENV_AGENT_REPORT_DIR: &str = "SPA_AGENT_REPORT_DIR";
const DOTENV_FILE_NAME: &str = ".env";
const DEFAULT_REPORT_NAME: &str = "Safety Protection Agent Report";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentConfig {
    pub markdown_report_dir: Option<PathBuf>,
}

impl AgentConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            markdown_report_dir: report_dir_from_process_env().or_else(report_dir_from_dotenv_file),
        })
    }

    pub fn write_markdown_report(
        &self,
        report_markdown: &str,
        report_name: Option<&str>,
    ) -> anyhow::Result<Option<PathBuf>> {
        let Some(dir) = &self.markdown_report_dir else {
            return Ok(None);
        };
        let report_markdown = report_markdown.trim();

        let dir = resolve_report_dir(dir)?;
        fs::create_dir_all(&dir).map_err(|error| {
            anyhow::anyhow!(
                "failed to create report directory {}: {error}",
                dir.display()
            )
        })?;

        let path = unique_report_path(
            &dir,
            &report_filename_stem(report_markdown, report_name)
                .unwrap_or_else(|| sanitize_report_filename(DEFAULT_REPORT_NAME).unwrap()),
        );
        fs::write(&path, format!("{report_markdown}\n")).map_err(|error| {
            anyhow::anyhow!("failed to write report {}: {error}", path.display())
        })?;

        Ok(Some(path))
    }
}

fn report_dir_from_process_env() -> Option<PathBuf> {
    std::env::var_os(ENV_AGENT_REPORT_DIR).and_then(non_empty_path_from_os_string)
}

fn non_empty_path_from_os_string(value: std::ffi::OsString) -> Option<PathBuf> {
    let value = value.to_string_lossy().trim().to_owned();
    (!value.is_empty()).then_some(PathBuf::from(value))
}

fn report_dir_from_dotenv_file() -> Option<PathBuf> {
    let raw = fs::read_to_string(DOTENV_FILE_NAME).ok()?;
    report_dir_from_dotenv_contents(&raw)
}

fn report_dir_from_dotenv_contents(raw: &str) -> Option<PathBuf> {
    raw.lines().find_map(|line| {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let (key, value) = line.split_once('=')?;
        if key.trim() != ENV_AGENT_REPORT_DIR {
            return None;
        }

        let value = value.trim().trim_matches(['"', '\'']).trim();
        (!value.is_empty()).then_some(PathBuf::from(value))
    })
}

fn resolve_report_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    if dir.is_absolute() {
        return Ok(dir.to_path_buf());
    }

    Ok(std::env::current_dir()
        .map_err(|error| anyhow::anyhow!("failed to resolve current directory: {error}"))?
        .join(dir))
}

fn unique_report_path(dir: &Path, stem: &str) -> PathBuf {
    let first = dir.join(format!("{stem}.md"));
    if !first.exists() {
        return first;
    }

    for index in 2.. {
        let candidate = dir.join(format!("{stem}-{index}.md"));
        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!("unbounded report path suffix search should always return")
}

fn report_filename_stem(report_markdown: &str, report_name: Option<&str>) -> Option<String> {
    report_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| extract_report_name(report_markdown))
        .or_else(|| extract_first_h1(report_markdown))
        .and_then(|name| sanitize_report_filename(&name))
}

fn extract_report_name(markdown: &str) -> Option<String> {
    for line in markdown.lines().take(40) {
        let line = trim_markdown_line_prefix(line);
        let lower = line.to_lowercase();
        for label in ["报告名称", "报告名", "report name", "report title"] {
            if let Some(rest) = lower.strip_prefix(label) {
                let offset = line.len() - rest.len();
                let value = line[offset..]
                    .trim_start_matches(|ch: char| ch == ':' || ch == '：' || ch.is_whitespace())
                    .trim();
                if !value.is_empty() {
                    return Some(strip_inline_markdown(value).to_owned());
                }
            }
        }
    }

    None
}

fn extract_first_h1(markdown: &str) -> Option<String> {
    markdown.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with("# ") {
            let title = strip_inline_markdown(line.trim_start_matches("# ").trim());
            (!title.is_empty()).then_some(title.to_owned())
        } else {
            None
        }
    })
}

fn trim_markdown_line_prefix(line: &str) -> &str {
    line.trim()
        .trim_start_matches('#')
        .trim_start_matches(['-', '*'])
        .trim()
}

fn strip_inline_markdown(value: &str) -> &str {
    value
        .trim()
        .trim_matches('`')
        .trim_matches('*')
        .trim_matches('_')
        .trim()
}

fn sanitize_report_filename(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut last_separator = false;

    for ch in value.chars() {
        let keep = ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.');
        if keep {
            output.push(ch);
            last_separator = false;
        } else if !last_separator {
            output.push('-');
            last_separator = true;
        }

        if output.chars().count() >= 96 {
            break;
        }
    }

    let output = output
        .trim_matches(|ch| matches!(ch, '-' | '_' | '.' | ' '))
        .to_owned();
    if output.is_empty() {
        return None;
    }

    if is_windows_reserved_filename(&output) {
        Some(format!("{output}-report"))
    } else {
        Some(output)
    }
}

fn is_windows_reserved_filename(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_markdown_report_creates_parent_directory() {
        let root = std::env::temp_dir().join(format!("spa-report-test-{}", uuid::Uuid::new_v4()));
        let dir = root.join("reports");
        let config = AgentConfig {
            markdown_report_dir: Some(dir.clone()),
        };

        let written = config
            .write_markdown_report(
                "报告名称：目标安全检测报告\n\n## 样本覆盖\n\n1 endpoint.\n\n## 攻击类型\n\nXSS.\n\n## 修复建议\n\nEncode output.",
                None,
            )
            .expect("report should write")
            .expect("configured path should be returned");

        assert_eq!(written.parent(), Some(dir.as_path()));
        assert_eq!(
            written.extension().and_then(|value| value.to_str()),
            Some("md")
        );
        assert!(
            written
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name == "目标安全检测报告.md")
        );
        let raw = fs::read_to_string(&written).expect("report should be readable");
        assert!(raw.contains("目标安全检测报告"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_markdown_report_uses_explicit_report_name() {
        let root = std::env::temp_dir().join(format!("spa-report-test-{}", uuid::Uuid::new_v4()));
        let config = AgentConfig {
            markdown_report_dir: Some(root.clone()),
        };

        let written = config
            .write_markdown_report("# Body\n\nReport body.", Some("显式报告名称"))
            .expect("report should write")
            .expect("configured path should be returned");

        assert_eq!(
            written.file_name().and_then(|value| value.to_str()),
            Some("显式报告名称.md")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn filename_uses_explicit_report_name() {
        let stem = report_filename_stem(
            "报告名称：本地护士排班系统 SQL 注入检测报告\n\n## 样本覆盖\n...",
            None,
        )
        .expect("report name should produce filename");

        assert_eq!(stem, "本地护士排班系统-SQL-注入检测报告");
    }

    #[test]
    fn filename_falls_back_to_h1() {
        let stem = report_filename_stem("# Target API Security Review\n\nBody", None)
            .expect("h1 should produce filename");

        assert_eq!(stem, "Target-API-Security-Review");
    }

    #[test]
    fn filename_sanitizes_path_separators_and_reserved_names() {
        assert_eq!(
            sanitize_report_filename("../CON: local/web? test*"),
            Some("CON-local-web-test".to_owned())
        );
        assert_eq!(
            sanitize_report_filename("CON"),
            Some("CON-report".to_owned())
        );
    }

    #[test]
    fn unique_report_path_adds_numeric_suffix_on_collision() {
        let root = std::env::temp_dir().join(format!("spa-report-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("dir should be created");
        fs::write(root.join("安全检测报告.md"), "first").expect("seed file should write");

        let path = unique_report_path(&root, "安全检测报告");

        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("安全检测报告-2.md")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dotenv_report_dir_preserves_windows_backslashes() {
        let dir = report_dir_from_dotenv_contents(
            r#"
LLM_PROVIDER=codex-chatgpt
SPA_AGENT_REPORT_DIR=D:\project\Safety-Protection-Agent\report
"#,
        )
        .expect("report dir should parse");

        assert_eq!(
            dir,
            PathBuf::from(r"D:\project\Safety-Protection-Agent\report")
        );
    }

    #[test]
    fn dotenv_report_dir_accepts_quoted_windows_path() {
        let dir = report_dir_from_dotenv_contents(
            r#"SPA_AGENT_REPORT_DIR="D:\project\Safety-Protection-Agent\report""#,
        )
        .expect("report dir should parse");

        assert_eq!(
            dir,
            PathBuf::from(r"D:\project\Safety-Protection-Agent\report")
        );
    }
}
