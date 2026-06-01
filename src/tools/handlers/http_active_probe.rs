use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolProgress, ToolProgressCallback,
    ToolSpec,
    risk::{DANGER, HIGH_RISK, NORMAL, WARNING},
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_MAX_PROBES: usize = 80;
const MAX_MAX_PROBES: usize = 160;
const MAX_FIELDS: usize = 12;
const MAX_PAYLOADS: usize = 12;
const BODY_PREVIEW_LIMIT: usize = 700;

#[derive(Debug, Clone, Copy)]
pub struct HttpActiveProbeScanTool;

#[async_trait]
impl ToolHandler for HttpActiveProbeScanTool {
    fn name(&self) -> &'static str {
        "http_active_probe_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Run bounded low-impact HTTP probes across query, header, cookie, and body inputs for web weakness classes that do not have a more specific SPA tool, including path traversal, command injection, LDAP injection, trust-boundary/state-key influence, and generic injection signals. Command-injection probes include shell separators and environment-variable command wrappers.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint to probe."
                    },
                    "probe_kind": {
                        "type": "string",
                        "description": "Focused weakness class to probe.",
                        "enum": ["path_traversal", "command_injection", "ldap_injection", "trust_boundary", "generic_injection"],
                        "default": "generic_injection"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method.",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Baseline request headers.",
                        "additionalProperties": { "type": "string" }
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Baseline cookies. Probe cookies are merged into this set.",
                        "additionalProperties": { "type": "string" }
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Baseline query parameters. Probe query values are merged into this set.",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "description": "Baseline request body. Object fields can be probed for non-GET methods."
                    },
                    "body_format": {
                        "type": "string",
                        "description": "How to send object bodies.",
                        "enum": ["auto", "json", "form"],
                        "default": "auto"
                    },
                    "input_locations": {
                        "type": "array",
                        "description": "Input locations to probe. Defaults to query, header, cookie, and body when a body is present.",
                        "items": {
                            "type": "string",
                            "enum": ["query", "header", "cookie", "body"]
                        }
                    },
                    "injectable_fields": {
                        "type": "array",
                        "description": "Field/header/cookie names to probe. Defaults to common benchmark and web parameter names such as vector, id, q, file, path, cmd, and token.",
                        "items": { "type": "string" }
                    },
                    "payloads": {
                        "type": "array",
                        "description": "Optional custom payloads. Defaults are selected from probe_kind.",
                        "items": { "type": "string" }
                    },
                    "stop_on_first_confirmed": {
                        "type": "boolean",
                        "description": "Stop once a high-confidence weakness-specific signal is observed.",
                        "default": false
                    },
                    "max_probes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_MAX_PROBES,
                        "default": DEFAULT_MAX_PROBES
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 500,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS
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

impl HttpActiveProbeScanTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: HttpActiveProbeInput =
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
struct HttpActiveProbeInput {
    url: String,
    #[serde(default)]
    probe_kind: ProbeKind,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    cookies: HashMap<String, String>,
    #[serde(default)]
    query_params: HashMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    body_format: BodyFormat,
    #[serde(default)]
    input_locations: Option<Vec<InputLocation>>,
    #[serde(default)]
    injectable_fields: Option<Vec<String>>,
    #[serde(default)]
    payloads: Option<Vec<String>>,
    #[serde(default)]
    stop_on_first_confirmed: bool,
    #[serde(default = "default_max_probes")]
    max_probes: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProbeKind {
    PathTraversal,
    CommandInjection,
    LdapInjection,
    TrustBoundary,
    #[default]
    GenericInjection,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputLocation {
    Query,
    Header,
    Cookie,
    Body,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BodyFormat {
    #[default]
    Auto,
    Json,
    Form,
}

#[derive(Clone)]
struct ProbePlan {
    url: Url,
    kind: ProbeKind,
    method: Method,
    headers: HeaderMap,
    cookies: HashMap<String, String>,
    query_params: HashMap<String, String>,
    body: Option<Value>,
    body_format: BodyFormat,
    locations: Vec<InputLocation>,
    fields: Vec<String>,
    payloads: Vec<ProbePayload>,
    stop_on_first_confirmed: bool,
    max_probes: usize,
    timeout_ms: u64,
}

#[derive(Clone)]
struct ProbePayload {
    value: String,
    marker: Option<String>,
}

impl HttpActiveProbeInput {
    fn into_plan(self, tool: &str) -> Result<ProbePlan> {
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

        let headers = parse_headers(tool, &self.headers)?;
        let locations = normalize_locations(self.input_locations, self.body.is_some());
        let fields = normalize_fields(self.injectable_fields, self.probe_kind);
        if fields.is_empty() {
            return Err(invalid(tool, "at least one injectable field is required"));
        }
        let payloads = normalize_payloads(self.payloads, self.probe_kind);
        if payloads.is_empty() {
            return Err(invalid(tool, "at least one payload is required"));
        }

        Ok(ProbePlan {
            url,
            kind: self.probe_kind,
            method,
            headers,
            cookies: self.cookies,
            query_params: self.query_params,
            body: self.body,
            body_format: self.body_format,
            locations,
            fields,
            payloads,
            stop_on_first_confirmed: self.stop_on_first_confirmed,
            max_probes: self.max_probes.clamp(1, MAX_MAX_PROBES),
            timeout_ms: self.timeout_ms.clamp(500, MAX_TIMEOUT_MS),
        })
    }
}

async fn run_scan(plan: ProbePlan, progress: Option<ToolProgressCallback>) -> ProbeReport {
    let client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(plan.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(4))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return ProbeReport::execution_error(
                plan.kind,
                format!("client build failed: {error}"),
            );
        }
    };

    let total_probes =
        (plan.locations.len() * plan.fields.len() * plan.payloads.len()).min(plan.max_probes) + 1;
    emit_progress(
        progress.as_ref(),
        &plan,
        "Sending baseline request",
        0,
        total_probes,
    );

    let baseline = match send_request(&client, &plan, None).await {
        Ok(response) => response,
        Err(error) => {
            return ProbeReport::execution_error(
                plan.kind,
                format!("baseline request failed: {error}"),
            );
        }
    };

    let mut observations = Vec::new();
    let mut completed = 1usize;
    let mut confirmed = false;

    'outer: for location in &plan.locations {
        for field in &plan.fields {
            for payload in &plan.payloads {
                if completed > plan.max_probes {
                    break 'outer;
                }

                let probe = ProbeAttempt {
                    location: *location,
                    field: field.clone(),
                    payload: payload.value.clone(),
                    marker: payload.marker.clone(),
                };
                emit_progress(
                    progress.as_ref(),
                    &plan,
                    &format!("Probing {} {}", location_label(*location), field),
                    completed,
                    total_probes,
                );

                let result = send_request(&client, &plan, Some(&probe)).await;
                completed += 1;

                match result {
                    Ok(response) => {
                        let signals = classify_signals(&plan.kind, &baseline, &response, &probe);
                        let high_confidence = signals.iter().any(|signal| {
                            matches!(
                                signal.as_str(),
                                "file_read_or_write_signal"
                                    | "command_output_marker_without_literal_payload"
                                    | "ldap_result_signal"
                                    | "session_attribute_influence_signal"
                            )
                        });
                        confirmed |= high_confidence;
                        observations
                            .push(ProbeObservation::from_response(probe, response, signals));

                        if high_confidence && plan.stop_on_first_confirmed {
                            break 'outer;
                        }
                    }
                    Err(error) => observations.push(ProbeObservation::from_error(probe, error)),
                }
            }
        }
    }

    emit_progress(
        progress.as_ref(),
        &plan,
        "Completed active probes",
        total_probes,
        total_probes,
    );

    ProbeReport {
        probe_kind: plan.kind,
        risk_level: report_risk_level(plan.kind, confirmed, &observations).to_owned(),
        baseline: BaselineSummary::from_response(baseline),
        tested_count: observations.len(),
        confirmed_signal_count: observations
            .iter()
            .filter(|observation| {
                observation
                    .signals
                    .iter()
                    .any(|signal| is_confirmed_signal(signal))
            })
            .count(),
        observations,
        error: None,
    }
}

fn emit_progress(
    progress: Option<&ToolProgressCallback>,
    plan: &ProbePlan,
    message: &str,
    completed: usize,
    total: usize,
) {
    if let Some(progress) = progress {
        progress(
            ToolProgress::new(
                "http_active_probe_scan",
                message,
                completed as u64,
                total as u64,
            )
            .with_metadata(json!({
                "probe_kind": plan.kind,
                "display_type": "checklist",
                "checklist": [
                    {"label": "baseline", "checked": completed > 0},
                    {"label": "bounded probes", "checked": completed >= total.saturating_sub(1)},
                    {"label": "signal classification", "checked": completed >= total}
                ],
                "checked_item": message
            })),
        );
    }
}

#[derive(Clone)]
struct ProbeAttempt {
    location: InputLocation,
    field: String,
    payload: String,
    marker: Option<String>,
}

struct ProbeResponse {
    status: u16,
    body: String,
    elapsed_ms: u128,
}

async fn send_request(
    client: &Client,
    plan: &ProbePlan,
    probe: Option<&ProbeAttempt>,
) -> anyhow::Result<ProbeResponse> {
    let started = Instant::now();
    let mut url = plan.url.clone();
    let mut query_params = plan.query_params.clone();
    let mut headers = plan.headers.clone();
    let mut cookies = plan.cookies.clone();
    let mut body = plan.body.clone();

    if let Some(probe) = probe {
        match probe.location {
            InputLocation::Query => {
                query_params.insert(probe.field.clone(), probe.payload.clone());
            }
            InputLocation::Header => {
                let name = HeaderName::from_str(&probe.field)?;
                let value = HeaderValue::from_str(&probe.payload)?;
                headers.insert(name, value);
            }
            InputLocation::Cookie => {
                cookies.insert(probe.field.clone(), probe.payload.clone());
            }
            InputLocation::Body => {
                body = Some(insert_body_field(body, &probe.field, &probe.payload));
            }
        }
    }

    if !query_params.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in query_params {
            pairs.append_pair(&name, &value);
        }
    }

    if !cookies.is_empty() {
        let cookie_value = cookies
            .iter()
            .map(|(name, value)| format!("{name}={}", percent_encode_cookie_value(value)))
            .collect::<Vec<_>>()
            .join("; ");
        headers.insert(COOKIE, HeaderValue::from_str(&cookie_value)?);
    }

    let mut request = client.request(plan.method.clone(), url).headers(headers);
    if let Some(body) = body
        && method_allows_body(&plan.method)
    {
        request = match plan.body_format {
            BodyFormat::Json => request.json(&body),
            BodyFormat::Form => request.form(&object_to_form_pairs(&body)),
            BodyFormat::Auto => {
                if body.is_object() {
                    request.form(&object_to_form_pairs(&body))
                } else {
                    request.json(&body)
                }
            }
        };
    }

    let response = request.send().await?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    Ok(ProbeResponse {
        status,
        body,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn method_allows_body(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn insert_body_field(body: Option<Value>, field: &str, payload: &str) -> Value {
    let mut object = match body {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    object.insert(field.to_owned(), Value::String(payload.to_owned()));
    Value::Object(object)
}

fn object_to_form_pairs(body: &Value) -> Vec<(String, String)> {
    match body {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn percent_encode_cookie_value(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(';', "%3B")
        .replace(['\r', '\n'], "")
}

fn classify_signals(
    kind: &ProbeKind,
    baseline: &ProbeResponse,
    response: &ProbeResponse,
    probe: &ProbeAttempt,
) -> Vec<String> {
    let mut signals = BTreeSet::new();
    let body = response.body.as_str();
    let lower = body.to_ascii_lowercase();
    let baseline_len = baseline.body.len() as isize;
    let response_len = response.body.len() as isize;

    if response.status != baseline.status {
        signals.insert("status_delta".to_owned());
    }
    if (response_len - baseline_len).abs() > 80 {
        signals.insert("body_length_delta".to_owned());
    }
    if body.contains(&probe.payload) {
        signals.insert("payload_reflected".to_owned());
    }

    match kind {
        ProbeKind::PathTraversal => {
            if lower.contains("the beginning of file")
                || lower.contains("fileinputstream")
                || lower.contains("now ready to write to file")
                || lower.contains("secret file")
                || lower.contains("safe text")
                || lower.contains("contents of")
                || lower.contains("web-app")
            {
                signals.insert("file_read_or_write_signal".to_owned());
            }
        }
        ProbeKind::CommandInjection => {
            if let Some(marker) = &probe.marker {
                if body.contains(marker) && !body.contains(&probe.payload) {
                    signals.insert("command_output_marker_without_literal_payload".to_owned());
                } else if body.contains(marker) {
                    signals.insert("command_marker_seen".to_owned());
                }
            }
            if lower.contains("uid=")
                || lower.contains("gid=")
                || lower.contains("microsoft windows")
                || lower.contains("volume serial number")
                || lower.contains("problem executing cmdi")
            {
                signals.insert("command_execution_output_signal".to_owned());
            }
        }
        ProbeKind::LdapInjection => {
            if lower.contains("ldap query results")
                || lower.contains("record found")
                || lower.contains("javax.naming")
            {
                signals.insert("ldap_result_signal".to_owned());
            }
        }
        ProbeKind::TrustBoundary => {
            if lower.contains("saved in session")
                || lower.contains("session")
                || (lower.contains("item:") && lower.contains("with value"))
            {
                signals.insert("session_attribute_influence_signal".to_owned());
            }
        }
        ProbeKind::GenericInjection => {}
    }

    signals.into_iter().collect()
}

fn is_confirmed_signal(signal: &str) -> bool {
    matches!(
        signal,
        "file_read_or_write_signal"
            | "command_output_marker_without_literal_payload"
            | "ldap_result_signal"
            | "session_attribute_influence_signal"
    )
}

fn report_risk_level(
    kind: ProbeKind,
    confirmed: bool,
    observations: &[ProbeObservation],
) -> &'static str {
    if confirmed {
        return match kind {
            ProbeKind::PathTraversal | ProbeKind::CommandInjection => HIGH_RISK,
            ProbeKind::LdapInjection | ProbeKind::TrustBoundary | ProbeKind::GenericInjection => {
                DANGER
            }
        };
    }
    if observations
        .iter()
        .any(|observation| !observation.signals.is_empty())
    {
        return WARNING;
    }
    NORMAL
}

#[derive(Debug, Serialize)]
struct ProbeReport {
    probe_kind: ProbeKind,
    risk_level: String,
    baseline: BaselineSummary,
    tested_count: usize,
    confirmed_signal_count: usize,
    observations: Vec<ProbeObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProbeReport {
    fn execution_error(kind: ProbeKind, error: String) -> Self {
        Self {
            probe_kind: kind,
            risk_level: WARNING.to_owned(),
            baseline: BaselineSummary::default(),
            tested_count: 0,
            confirmed_signal_count: 0,
            observations: Vec::new(),
            error: Some(error),
        }
    }

    fn summary(&self) -> String {
        let mut lines = vec![
            format!("HTTP active probe kind: {:?}", self.probe_kind),
            format!("Risk level: {}", self.risk_level),
            format!("Baseline status: {}", self.baseline.status),
            format!("Tested probes: {}", self.tested_count),
            format!("Confirmed signal count: {}", self.confirmed_signal_count),
        ];
        if let Some(error) = &self.error {
            lines.push(format!("Error: {error}"));
        }
        for observation in self.observations.iter().take(8) {
            if !observation.signals.is_empty() || observation.error.is_some() {
                lines.push(format!(
                    "- {} {} payload=`{}` status={} signals={}",
                    location_label(observation.location),
                    observation.field,
                    observation.payload_preview,
                    observation
                        .status
                        .map(|status| status.to_string())
                        .unwrap_or_else(|| "n/a".to_owned()),
                    if observation.signals.is_empty() {
                        observation.error.as_deref().unwrap_or("none").to_owned()
                    } else {
                        observation.signals.join(", ")
                    }
                ));
            }
        }
        lines.join("\n")
    }
}

#[derive(Debug, Default, Serialize)]
struct BaselineSummary {
    status: u16,
    body_len: usize,
    elapsed_ms: u128,
}

impl BaselineSummary {
    fn from_response(response: ProbeResponse) -> Self {
        Self {
            status: response.status,
            body_len: response.body.len(),
            elapsed_ms: response.elapsed_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProbeObservation {
    location: InputLocation,
    field: String,
    payload_preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u128>,
    signals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProbeObservation {
    fn from_response(probe: ProbeAttempt, response: ProbeResponse, signals: Vec<String>) -> Self {
        let body_excerpt = if signals.is_empty() {
            None
        } else {
            Some(truncate_body(&response.body, BODY_PREVIEW_LIMIT))
        };

        Self {
            location: probe.location,
            field: probe.field,
            payload_preview: truncate_body(&probe.payload, 140),
            status: Some(response.status),
            body_len: Some(response.body.len()),
            elapsed_ms: Some(response.elapsed_ms),
            signals,
            body_excerpt,
            error: None,
        }
    }

    fn from_error(probe: ProbeAttempt, error: anyhow::Error) -> Self {
        Self {
            location: probe.location,
            field: probe.field,
            payload_preview: truncate_body(&probe.payload, 140),
            status: None,
            body_len: None,
            elapsed_ms: None,
            signals: Vec::new(),
            body_excerpt: None,
            error: Some(error.to_string()),
        }
    }
}

fn truncate_body(value: &str, limit: usize) -> String {
    let value = value.replace('\r', "\\r").replace('\n', "\\n");
    if value.chars().count() <= limit {
        return value;
    }
    let mut output = value
        .chars()
        .take(limit.saturating_sub(3))
        .collect::<String>();
    output.push_str("...");
    output
}

fn parse_headers(tool: &str, input: &HashMap<String, String>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in input {
        let name = HeaderName::from_str(name)
            .map_err(|error| invalid(tool, format!("invalid header name {name}: {error}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| invalid(tool, format!("invalid header value for {name}: {error}")))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn normalize_locations(
    locations: Option<Vec<InputLocation>>,
    has_body: bool,
) -> Vec<InputLocation> {
    let mut output = locations.unwrap_or_else(|| {
        let mut defaults = vec![
            InputLocation::Query,
            InputLocation::Header,
            InputLocation::Cookie,
        ];
        if has_body {
            defaults.push(InputLocation::Body);
        }
        defaults
    });
    output.sort_by_key(|location| match location {
        InputLocation::Query => 0,
        InputLocation::Header => 1,
        InputLocation::Cookie => 2,
        InputLocation::Body => 3,
    });
    output.dedup();
    output
}

fn normalize_fields(fields: Option<Vec<String>>, kind: ProbeKind) -> Vec<String> {
    let defaults = match kind {
        ProbeKind::PathTraversal => vec![
            "vector", "file", "filename", "path", "name", "value", "input", "id",
        ],
        ProbeKind::CommandInjection => {
            vec![
                "vector", "cmd", "command", "exec", "input", "q", "name", "value",
            ]
        }
        ProbeKind::LdapInjection => {
            vec![
                "vector", "uid", "user", "username", "name", "search", "q", "filter",
            ]
        }
        ProbeKind::TrustBoundary => {
            vec![
                "vector", "token", "name", "key", "role", "user", "session", "id",
            ]
        }
        ProbeKind::GenericInjection => vec![
            "vector", "id", "q", "query", "search", "name", "value", "input", "token",
        ],
    };
    let raw = fields.unwrap_or_else(|| defaults.into_iter().map(ToOwned::to_owned).collect());
    dedup_trimmed(raw, MAX_FIELDS)
}

fn normalize_payloads(payloads: Option<Vec<String>>, kind: ProbeKind) -> Vec<ProbePayload> {
    let generated = match payloads {
        Some(payloads) => payloads
            .into_iter()
            .map(|value| ProbePayload {
                value,
                marker: None,
            })
            .collect(),
        None => default_payloads(kind),
    };

    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for payload in generated {
        let value = payload.value.trim();
        if value.is_empty() || !seen.insert(value.to_owned()) {
            continue;
        }
        output.push(ProbePayload {
            value: value.to_owned(),
            marker: payload.marker,
        });
        if output.len() >= MAX_PAYLOADS {
            break;
        }
    }
    output
}

fn default_payloads(kind: ProbeKind) -> Vec<ProbePayload> {
    let nonce = uuid::Uuid::new_v4()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>();
    match kind {
        ProbeKind::PathTraversal => [
            "FileName",
            "SafeText",
            "SecretFile",
            "../SecretFile",
            "..%2fSecretFile",
            "../../etc/passwd",
            "../WEB-INF/web.xml",
        ]
        .into_iter()
        .map(payload)
        .collect(),
        ProbeKind::CommandInjection => {
            let marker = format!("spa_cmd_{nonce}");
            vec![
                payload(format!("spa_probe_{nonce}")),
                marked_payload(format!("spa_probe_{nonce}&&echo {marker}"), marker.clone()),
                marked_payload(format!("spa_probe_{nonce};echo {marker}"), marker.clone()),
                marked_payload(format!("spa_probe_{nonce}|echo {marker}"), marker.clone()),
                marked_payload(format!("FOO=echo {marker}"), marker),
            ]
        }
        ProbeKind::LdapInjection => ["*", "*)", "*)(uid=*))(|(uid=*", "benchmark"]
            .into_iter()
            .map(payload)
            .chain(std::iter::once(payload(format!("spa_ldap_{nonce}"))))
            .collect(),
        ProbeKind::TrustBoundary => vec![
            payload(format!("spa_attr_{nonce}")),
            payload("role"),
            payload("admin"),
            payload("session"),
            payload("tenant"),
        ],
        ProbeKind::GenericInjection => vec![
            payload(format!("spa_probe_{nonce}")),
            payload("'"),
            payload("\""),
            payload("<spa-probe>"),
            payload("../SecretFile"),
        ],
    }
}

fn payload(value: impl Into<String>) -> ProbePayload {
    ProbePayload {
        value: value.into(),
        marker: None,
    }
}

fn marked_payload(value: impl Into<String>, marker: String) -> ProbePayload {
    ProbePayload {
        value: value.into(),
        marker: Some(marker),
    }
}

fn dedup_trimmed(values: Vec<String>, limit: usize) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || !seen.insert(value.to_ascii_lowercase()) {
            continue;
        }
        output.push(value.to_owned());
        if output.len() >= limit {
            break;
        }
    }
    output
}

fn location_label(location: InputLocation) -> &'static str {
    match location {
        InputLocation::Query => "query",
        InputLocation::Header => "header",
        InputLocation::Cookie => "cookie",
        InputLocation::Body => "body",
    }
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

fn default_max_probes() -> usize {
    DEFAULT_MAX_PROBES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_injection_marker_without_literal_is_confirmed_signal() {
        let baseline = ProbeResponse {
            status: 200,
            body: "ok".to_owned(),
            elapsed_ms: 1,
        };
        let response = ProbeResponse {
            status: 200,
            body: "spa_probe\nspa_cmd_abcd".to_owned(),
            elapsed_ms: 1,
        };
        let probe = ProbeAttempt {
            location: InputLocation::Header,
            field: "vector".to_owned(),
            payload: "spa_probe&&echo spa_cmd_abcd".to_owned(),
            marker: Some("spa_cmd_abcd".to_owned()),
        };

        let signals = classify_signals(&ProbeKind::CommandInjection, &baseline, &response, &probe);

        assert!(signals.contains(&"command_output_marker_without_literal_payload".to_owned()));
    }

    #[test]
    fn command_injection_defaults_include_environment_wrapper_payload() {
        let payloads = default_payloads(ProbeKind::CommandInjection);

        assert!(payloads.iter().any(|payload| {
            payload.value.starts_with("FOO=echo ")
                && payload
                    .marker
                    .as_ref()
                    .is_some_and(|marker| payload.value.ends_with(marker))
        }));
    }

    #[test]
    fn path_traversal_file_response_is_confirmed_signal() {
        let baseline = ProbeResponse {
            status: 200,
            body: "Problem getting FileInputStream".to_owned(),
            elapsed_ms: 1,
        };
        let response = ProbeResponse {
            status: 200,
            body: "The beginning of file: SecretFile is: secret file".to_owned(),
            elapsed_ms: 1,
        };
        let probe = ProbeAttempt {
            location: InputLocation::Cookie,
            field: "vector".to_owned(),
            payload: "SecretFile".to_owned(),
            marker: None,
        };

        let signals = classify_signals(&ProbeKind::PathTraversal, &baseline, &response, &probe);

        assert!(signals.contains(&"file_read_or_write_signal".to_owned()));
    }

    #[test]
    fn defaults_include_benchmark_vector_field() {
        let fields = normalize_fields(None, ProbeKind::PathTraversal);

        assert!(fields.contains(&"vector".to_owned()));
        assert!(fields.contains(&"file".to_owned()));
    }
}
