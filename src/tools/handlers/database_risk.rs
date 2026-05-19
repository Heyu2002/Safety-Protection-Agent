use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolProgress, ToolProgressCallback,
    ToolSpec,
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_TIME_DELAY_MS: u64 = 1_500;
const MAX_TIME_DELAY_MS: u64 = 3_000;
const MAX_FIELDS: usize = 12;
const BODY_PREVIEW_LIMIT: usize = 2_000;

#[derive(Debug, Clone, Copy)]
pub struct DatabaseRiskScanTool;

#[async_trait]
impl ToolHandler for DatabaseRiskScanTool {
    fn name(&self) -> &'static str {
        "database_risk_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Probe an HTTP endpoint for database attack surface signals such as SQL error leakage, boolean response differences, and optional time-delay behavior.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint to scan."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method.",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers.",
                        "additionalProperties": { "type": "string" }
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Additional query parameters to include when scanning.",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "description": "Optional JSON request body. Object fields can be selected as injectable fields."
                    },
                    "injectable_fields": {
                        "type": "array",
                        "description": "Parameter or top-level JSON body field names to test. Defaults to detected URL query/body fields.",
                        "items": { "type": "string" }
                    },
                    "include_time_based": {
                        "type": "boolean",
                        "description": "Whether to include short time-delay probes.",
                        "default": true
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 500,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS
                    },
                    "max_time_delay_ms": {
                        "type": "integer",
                        "minimum": 500,
                        "maximum": MAX_TIME_DELAY_MS,
                        "default": DEFAULT_TIME_DELAY_MS
                    }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        self.run(call, None).await
    }

    async fn handle_with_progress(
        &self,
        call: ToolCall,
        progress: ToolProgressCallback,
    ) -> Result<ToolOutput> {
        self.run(call, Some(progress)).await
    }
}

impl DatabaseRiskScanTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: DatabaseRiskInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;
        let plan = input.into_plan(self.name())?;
        let report = run_scan(plan, progress).await;
        let metadata = serde_json::to_value(&report).map_err(|error| ToolError::Execution {
            tool: self.name().to_owned(),
            message: error.to_string(),
        })?;

        Ok(ToolOutput::text(call.id, report.summary()).with_metadata(metadata))
    }
}

#[derive(Debug, Deserialize)]
struct DatabaseRiskInput {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    query_params: HashMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    injectable_fields: Option<Vec<String>>,
    #[serde(default = "default_include_time_based")]
    include_time_based: bool,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_time_delay_ms")]
    max_time_delay_ms: u64,
}

#[derive(Clone)]
struct ScanPlan {
    url: Url,
    method: Method,
    headers: HeaderMap,
    query_params: HashMap<String, String>,
    body: Option<Value>,
    fields: Vec<String>,
    include_time_based: bool,
    timeout_ms: u64,
    max_time_delay_ms: u64,
}

impl DatabaseRiskInput {
    fn into_plan(self, tool: &str) -> Result<ScanPlan> {
        let url = Url::parse(&self.url).map_err(|error| invalid(tool, error.to_string()))?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => return Err(invalid(tool, format!("unsupported URL scheme: {scheme}"))),
        }

        let method = Method::from_str(&self.method.to_ascii_uppercase())
            .map_err(|error| invalid(tool, error.to_string()))?;
        if !matches!(
            method,
            Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return Err(invalid(tool, format!("unsupported HTTP method: {method}")));
        }

        let mut headers = HeaderMap::new();
        for (name, value) in self.headers {
            let name =
                HeaderName::from_str(&name).map_err(|error| invalid(tool, error.to_string()))?;
            let value =
                HeaderValue::from_str(&value).map_err(|error| invalid(tool, error.to_string()))?;
            headers.insert(name, value);
        }

        let fields = selected_fields(
            &url,
            &self.query_params,
            self.body.as_ref(),
            self.injectable_fields,
        );
        if fields.len() > MAX_FIELDS {
            return Err(invalid(
                tool,
                format!("injectable_fields must contain at most {MAX_FIELDS} fields"),
            ));
        }

        Ok(ScanPlan {
            url,
            method,
            headers,
            query_params: self.query_params,
            body: self.body,
            fields,
            include_time_based: self.include_time_based,
            timeout_ms: bounded(tool, "timeout_ms", self.timeout_ms, 500, MAX_TIMEOUT_MS)?,
            max_time_delay_ms: bounded(
                tool,
                "max_time_delay_ms",
                self.max_time_delay_ms,
                500,
                MAX_TIME_DELAY_MS,
            )?,
        })
    }
}

async fn run_scan(plan: ScanPlan, progress: Option<ToolProgressCallback>) -> DatabaseRiskReport {
    let client = Client::builder()
        .timeout(Duration::from_millis(plan.timeout_ms))
        .build()
        .unwrap_or_else(|_| Client::new());
    let baseline = send_probe(&client, &plan, None, None).await;
    let checklist = scan_checklist(&plan.fields, plan.include_time_based);
    let total = checklist.len() as u64;
    let mut completed = 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    if plan.fields.is_empty() {
        return DatabaseRiskReport::empty(plan, baseline);
    }

    let mut findings = Vec::new();
    for field in &plan.fields {
        let error_probe = send_probe(&client, &plan, Some(field), Some("'")).await;
        completed += 1;
        emit_progress(progress.as_ref(), completed, total, &checklist);

        let boolean_true = send_probe(&client, &plan, Some(field), Some("' OR '1'='1")).await;
        completed += 1;
        emit_progress(progress.as_ref(), completed, total, &checklist);

        let boolean_false = send_probe(&client, &plan, Some(field), Some("' AND '1'='2")).await;
        completed += 1;
        emit_progress(progress.as_ref(), completed, total, &checklist);

        let time_probe = if plan.include_time_based {
            let probe = send_probe(&client, &plan, Some(field), Some("' OR SLEEP(1)--")).await;
            completed += 1;
            emit_progress(progress.as_ref(), completed, total, &checklist);
            Some(probe)
        } else {
            None
        };

        findings.push(analyze_field(
            field,
            &baseline,
            &error_probe,
            &boolean_true,
            &boolean_false,
            time_probe.as_ref(),
            plan.max_time_delay_ms,
        ));
    }

    DatabaseRiskReport::from_findings(plan, baseline, findings)
}

async fn send_probe(
    client: &Client,
    plan: &ScanPlan,
    field: Option<&str>,
    payload: Option<&str>,
) -> ProbeObservation {
    let started = tokio::time::Instant::now();
    let mut url = plan.url.clone();
    apply_query_params(&mut url, &plan.query_params);

    let mut body = plan.body.clone();
    if let (Some(field), Some(payload)) = (field, payload) {
        if mutates_body_field(body.as_mut(), field, payload) {
            // Body field was mutated.
        } else {
            upsert_query_param(&mut url, field, payload);
        }
    }

    let mut request = client
        .request(plan.method.clone(), url)
        .headers(plan.headers.clone());
    if let Some(body) = body {
        request = request.json(&body);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            ProbeObservation {
                status: Some(status),
                latency_ms: started.elapsed().as_millis() as u64,
                body_len: body.len(),
                body_preview: body.chars().take(BODY_PREVIEW_LIMIT).collect(),
                error: None,
            }
        }
        Err(error) => ProbeObservation {
            status: None,
            latency_ms: started.elapsed().as_millis() as u64,
            body_len: 0,
            body_preview: String::new(),
            error: Some(error.to_string()),
        },
    }
}

fn analyze_field(
    field: &str,
    baseline: &ProbeObservation,
    error_probe: &ProbeObservation,
    boolean_true: &ProbeObservation,
    boolean_false: &ProbeObservation,
    time_probe: Option<&ProbeObservation>,
    max_time_delay_ms: u64,
) -> FieldFinding {
    let mut signals = Vec::new();

    if let Some(pattern) = database_error_pattern(&error_probe.body_preview) {
        signals.push(RiskSignal {
            kind: "database_error_leak".to_owned(),
            severity: "high".to_owned(),
            evidence: format!("response contained database error pattern: {pattern}"),
        });
    }

    let baseline_usable = is_usable_baseline(baseline);
    if !baseline_usable {
        signals.push(RiskSignal {
            kind: "baseline_unavailable".to_owned(),
            severity: "info".to_owned(),
            evidence: format!(
                "baseline request was not a usable business response: status {:?}, error {:?}",
                baseline.status, baseline.error
            ),
        });
    }

    if baseline_usable && status_changed(baseline, error_probe) {
        signals.push(RiskSignal {
            kind: "status_change_on_quote".to_owned(),
            severity: "medium".to_owned(),
            evidence: format!(
                "baseline status {:?}, quote probe status {:?}",
                baseline.status, error_probe.status
            ),
        });
    }

    let true_false_delta = body_len_delta(boolean_true, boolean_false);
    if baseline_usable && (true_false_delta > 0.30 || boolean_true.status != boolean_false.status) {
        signals.push(RiskSignal {
            kind: "boolean_response_difference".to_owned(),
            severity: "medium".to_owned(),
            evidence: format!(
                "true/false probes differed: statuses {:?}/{:?}, body lengths {}/{}",
                boolean_true.status,
                boolean_false.status,
                boolean_true.body_len,
                boolean_false.body_len
            ),
        });
    }

    if baseline_usable && let Some(time_probe) = time_probe {
        let delta = time_probe.latency_ms.saturating_sub(baseline.latency_ms);
        if delta >= max_time_delay_ms {
            signals.push(RiskSignal {
                kind: "time_delay_signal".to_owned(),
                severity: "medium".to_owned(),
                evidence: format!(
                    "time probe latency {} ms vs baseline {} ms",
                    time_probe.latency_ms, baseline.latency_ms
                ),
            });
        }
    }

    let risk = risk_from_signals(&signals);
    FieldFinding {
        field: field.to_owned(),
        risk,
        signals,
    }
}

#[derive(Debug, Serialize)]
struct DatabaseRiskReport {
    url: String,
    method: String,
    tested_fields: Vec<String>,
    risk_level: String,
    summary: String,
    baseline: ProbeSummary,
    findings: Vec<FieldFinding>,
    recommendations: Vec<String>,
}

impl DatabaseRiskReport {
    fn empty(plan: ScanPlan, baseline: ProbeObservation) -> Self {
        Self {
            url: plan.url.to_string(),
            method: plan.method.to_string(),
            tested_fields: Vec::new(),
            risk_level: "unknown".to_owned(),
            summary: "No injectable query or body fields were provided or detected.".to_owned(),
            baseline: ProbeSummary::from_observation(&baseline),
            findings: Vec::new(),
            recommendations: vec![
                "Provide injectable_fields for the parameters that reach database queries."
                    .to_owned(),
                "Run with representative query parameters or JSON body values.".to_owned(),
            ],
        }
    }

    fn from_findings(
        plan: ScanPlan,
        baseline: ProbeObservation,
        findings: Vec<FieldFinding>,
    ) -> Self {
        let risk_level = aggregate_risk(&findings);
        let risky_fields = findings
            .iter()
            .filter(|finding| finding.risk != "low")
            .count();
        Self {
            url: plan.url.to_string(),
            method: plan.method.to_string(),
            tested_fields: plan.fields,
            risk_level: risk_level.to_owned(),
            summary: format!(
                "Database attack surface scan completed: {risky_fields} risky field(s), overall risk {risk_level}."
            ),
            baseline: ProbeSummary::from_observation(&baseline),
            findings,
            recommendations: recommendations_for(risk_level),
        }
    }

    fn summary(&self) -> String {
        self.summary.to_owned()
    }
}

#[derive(Debug, Serialize)]
struct FieldFinding {
    field: String,
    risk: String,
    signals: Vec<RiskSignal>,
}

#[derive(Debug, Serialize)]
struct RiskSignal {
    kind: String,
    severity: String,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct ProbeSummary {
    status: Option<u16>,
    latency_ms: u64,
    body_len: usize,
    error: Option<String>,
}

impl ProbeSummary {
    fn from_observation(observation: &ProbeObservation) -> Self {
        Self {
            status: observation.status,
            latency_ms: observation.latency_ms,
            body_len: observation.body_len,
            error: observation.error.clone(),
        }
    }
}

#[derive(Debug)]
struct ProbeObservation {
    status: Option<u16>,
    latency_ms: u64,
    body_len: usize,
    body_preview: String,
    error: Option<String>,
}

fn selected_fields(
    url: &Url,
    query_params: &HashMap<String, String>,
    body: Option<&Value>,
    requested: Option<Vec<String>>,
) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(requested) = requested {
        for field in requested {
            push_unique(&mut fields, field);
        }
        return fields;
    }

    for (name, _) in url.query_pairs() {
        push_unique(&mut fields, name.to_string());
    }
    for name in query_params.keys() {
        push_unique(&mut fields, name.to_owned());
    }
    if let Some(Value::Object(map)) = body {
        for name in map.keys() {
            push_unique(&mut fields, name.to_owned());
        }
    }

    fields
}

fn push_unique(items: &mut Vec<String>, item: String) {
    if !item.is_empty() && !items.contains(&item) {
        items.push(item);
    }
}

fn apply_query_params(url: &mut Url, params: &HashMap<String, String>) {
    if params.is_empty() {
        return;
    }
    let mut pairs: BTreeMap<String, String> = url
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    for (name, value) in params {
        pairs.insert(name.to_owned(), value.to_owned());
    }
    url.set_query(None);
    for (name, value) in pairs {
        url.query_pairs_mut().append_pair(&name, &value);
    }
}

fn upsert_query_param(url: &mut Url, field: &str, value: &str) {
    let mut pairs: BTreeMap<String, String> = url
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    pairs.insert(field.to_owned(), value.to_owned());
    url.set_query(None);
    for (name, value) in pairs {
        url.query_pairs_mut().append_pair(&name, &value);
    }
}

fn mutates_body_field(body: Option<&mut Value>, field: &str, payload: &str) -> bool {
    let Some(Value::Object(map)) = body else {
        return false;
    };
    if !map.contains_key(field) {
        return false;
    }
    map.insert(field.to_owned(), Value::String(payload.to_owned()));
    true
}

fn database_error_pattern(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    for pattern in [
        "sql syntax",
        "mysql",
        "postgresql",
        "sqlite",
        "ora-",
        "odbc",
        "jdbc",
        "unterminated quoted string",
        "syntax error at or near",
        "you have an error in your sql syntax",
    ] {
        if lower.contains(pattern) {
            return Some(pattern);
        }
    }
    None
}

fn status_changed(left: &ProbeObservation, right: &ProbeObservation) -> bool {
    left.status != right.status && right.status.map(|status| status >= 500).unwrap_or(false)
}

fn is_usable_baseline(observation: &ProbeObservation) -> bool {
    observation.error.is_none()
        && observation
            .status
            .map(|status| status < 500)
            .unwrap_or(false)
}

fn body_len_delta(left: &ProbeObservation, right: &ProbeObservation) -> f64 {
    let max = left.body_len.max(right.body_len).max(1) as f64;
    let min = left.body_len.min(right.body_len) as f64;
    (max - min) / max
}

fn risk_from_signals(signals: &[RiskSignal]) -> String {
    if signals.iter().any(|signal| signal.severity == "high") {
        "high".to_owned()
    } else if signals.iter().any(|signal| signal.severity == "medium") {
        "medium".to_owned()
    } else {
        "low".to_owned()
    }
}

fn aggregate_risk(findings: &[FieldFinding]) -> &'static str {
    if findings.iter().any(|finding| finding.risk == "high") {
        "high"
    } else if findings.iter().any(|finding| finding.risk == "medium") {
        "medium"
    } else {
        "low"
    }
}

fn recommendations_for(risk_level: &str) -> Vec<String> {
    let mut recommendations = vec![
        "Use parameterized queries or ORM bind parameters for all database access.".to_owned(),
        "Return generic application errors instead of raw database errors.".to_owned(),
        "Add integration tests that exercise malicious input for database-backed parameters."
            .to_owned(),
    ];
    if risk_level != "low" {
        recommendations.push(
            "Review the flagged fields first and validate them against the database query path."
                .to_owned(),
        );
    }
    recommendations
}

fn scan_checklist(fields: &[String], include_time_based: bool) -> Vec<String> {
    let mut checklist = vec!["Baseline request".to_owned()];
    for field in fields {
        checklist.push(format!("{field}: quote/error leakage probe"));
        checklist.push(format!("{field}: boolean true probe"));
        checklist.push(format!("{field}: boolean false probe"));
        if include_time_based {
            checklist.push(format!("{field}: time-delay probe"));
        }
    }
    checklist
}

fn emit_progress(
    progress: Option<&ToolProgressCallback>,
    completed: u64,
    total: u64,
    checklist: &[String],
) {
    let Some(progress) = progress else {
        return;
    };
    let checked_index = completed.saturating_sub(1) as usize;
    let checked_item = checklist.get(checked_index).cloned().unwrap_or_default();
    let items: Vec<_> = checklist
        .iter()
        .enumerate()
        .map(|(index, label)| {
            json!({
                "label": label,
                "checked": index < completed as usize
            })
        })
        .collect();

    progress(
        ToolProgress::new(
            "database_risk_scan",
            format!("checked: {checked_item}"),
            completed,
            total,
        )
        .with_metadata(json!({
            "display_type": "checklist",
            "checked_item": checked_item,
            "checklist": items
        })),
    );
}

fn bounded(tool: &str, field: &str, value: u64, min: u64, max: u64) -> Result<u64> {
    if value < min || value > max {
        return Err(invalid(
            tool,
            format!("{field} must be between {min} and {max}"),
        ));
    }
    Ok(value)
}

fn invalid(tool: &str, message: impl Into<String>) -> ToolError {
    ToolError::InvalidInput {
        tool: tool.to_owned(),
        message: message.into(),
    }
}

fn default_method() -> String {
    "GET".to_owned()
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_time_delay_ms() -> u64 {
    DEFAULT_TIME_DELAY_MS
}

fn default_include_time_based() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolRegistry;

    #[test]
    fn detects_database_error_patterns() {
        assert_eq!(
            database_error_pattern("You have an error in your SQL syntax near quote"),
            Some("sql syntax")
        );
    }

    #[test]
    fn selects_query_and_body_fields() {
        let url = Url::parse("http://localhost/search?id=1").expect("url should parse");
        let body = json!({ "name": "alice" });
        let fields = selected_fields(&url, &HashMap::new(), Some(&body), None);

        assert_eq!(fields, vec!["id".to_owned(), "name".to_owned()]);
    }

    #[test]
    fn mutates_query_param_when_body_field_is_absent() {
        let mut url = Url::parse("http://localhost/search?id=1").expect("url should parse");

        upsert_query_param(&mut url, "id", "'");

        assert!(url.as_str().contains("id=%27"));
    }

    #[test]
    fn builds_scan_checklist_for_each_probe() {
        let fields = vec!["date".to_owned()];

        assert_eq!(
            scan_checklist(&fields, true),
            vec![
                "Baseline request".to_owned(),
                "date: quote/error leakage probe".to_owned(),
                "date: boolean true probe".to_owned(),
                "date: boolean false probe".to_owned(),
                "date: time-delay probe".to_owned(),
            ]
        );
        assert_eq!(scan_checklist(&fields, false).len(), 4);
    }

    #[tokio::test]
    async fn registry_includes_database_risk_scan() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("database_risk_scan"));
        assert!(registry.spec("database_risk_scan").is_some());
    }
}
