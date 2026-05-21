use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, SET_COOKIE};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{
    Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolProgress, ToolProgressCallback,
    ToolSpec,
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_SAMPLE_COUNT: u64 = 16;
const MAX_SAMPLE_COUNT: u64 = 100;
const DEFAULT_INTERVAL_MS: u64 = 250;
const MAX_INTERVAL_MS: u64 = 5_000;
const EPOCH_MATCH_WINDOW_SECS: u64 = 5;
const TIMESTAMP_NEAR_NOW_SECS: u64 = 300;

#[derive(Debug, Clone, Copy)]
pub struct WeakSessionIdScanTool;

#[async_trait]
impl ToolHandler for WeakSessionIdScanTool {
    fn name(&self) -> &'static str {
        "weak_session_id_scan"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Sample generated session IDs and detect weak, predictable, duplicate, sequential, timestamp, or md5(time) style identifiers.",
            json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTP or HTTPS endpoint that creates or refreshes the session identifier."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method.",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers, such as Cookie for an authenticated lab session.",
                        "additionalProperties": { "type": "string" }
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Additional query parameters to include on each sample request.",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "description": "Optional request body. Object fields can be sent as JSON or form data."
                    },
                    "body_format": {
                        "type": "string",
                        "description": "How to send object bodies. Use form for HTML/PHP lab forms, json for APIs, or auto to infer.",
                        "enum": ["auto", "json", "form"],
                        "default": "auto"
                    },
                    "token_name": {
                        "type": "string",
                        "description": "Optional cookie or response token name to analyze. If omitted, the scanner chooses the most likely changing Set-Cookie candidate."
                    },
                    "token_location": {
                        "type": "string",
                        "description": "Where to look for generated session IDs.",
                        "enum": ["auto", "set_cookie", "body"],
                        "default": "auto"
                    },
                    "sample_count": {
                        "type": "integer",
                        "minimum": 3,
                        "maximum": MAX_SAMPLE_COUNT,
                        "default": DEFAULT_SAMPLE_COUNT
                    },
                    "interval_ms": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_INTERVAL_MS,
                        "default": DEFAULT_INTERVAL_MS
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

impl WeakSessionIdScanTool {
    async fn run(
        &self,
        call: ToolCall,
        progress: Option<ToolProgressCallback>,
    ) -> Result<ToolOutput> {
        let input: WeakSessionIdInput =
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
struct WeakSessionIdInput {
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
    body_format: BodyFormat,
    #[serde(default)]
    token_name: Option<String>,
    #[serde(default)]
    token_location: TokenLocation,
    #[serde(default = "default_sample_count")]
    sample_count: u64,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BodyFormat {
    Auto,
    Json,
    Form,
}

impl Default for BodyFormat {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TokenLocation {
    Auto,
    SetCookie,
    Body,
}

impl Default for TokenLocation {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Clone)]
struct ScanPlan {
    url: Url,
    method: Method,
    headers: HeaderMap,
    query_params: HashMap<String, String>,
    body: Option<Value>,
    body_format: BodyFormat,
    token_name: Option<String>,
    token_location: TokenLocation,
    sample_count: u64,
    interval_ms: u64,
    timeout_ms: u64,
}

impl WeakSessionIdInput {
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

        Ok(ScanPlan {
            url,
            method,
            headers,
            query_params: self.query_params,
            body: self.body,
            body_format: self.body_format,
            token_name: self.token_name.filter(|name| !name.trim().is_empty()),
            token_location: self.token_location,
            sample_count: bounded(tool, "sample_count", self.sample_count, 3, MAX_SAMPLE_COUNT)?,
            interval_ms: bounded(tool, "interval_ms", self.interval_ms, 0, MAX_INTERVAL_MS)?,
            timeout_ms: bounded(tool, "timeout_ms", self.timeout_ms, 500, MAX_TIMEOUT_MS)?,
        })
    }
}

async fn run_scan(plan: ScanPlan, progress: Option<ToolProgressCallback>) -> WeakSessionIdReport {
    let client = Client::builder()
        .timeout(Duration::from_millis(plan.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut samples = Vec::with_capacity(plan.sample_count as usize);
    emit_progress(progress.as_ref(), 0, plan.sample_count, 0);

    for index in 1..=plan.sample_count {
        if index > 1 && plan.interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(plan.interval_ms)).await;
        }

        let sample = collect_sample(&client, &plan, index).await;
        samples.push(sample);
        let observed = samples
            .iter()
            .filter(|sample| !sample.candidates.is_empty())
            .count() as u64;
        emit_progress(progress.as_ref(), index, plan.sample_count, observed);
    }

    WeakSessionIdReport::from_samples(plan, samples)
}

async fn collect_sample(client: &Client, plan: &ScanPlan, index: u64) -> RawSample {
    let epoch_secs = now_epoch_secs();
    let started = tokio::time::Instant::now();
    let mut url = plan.url.clone();
    apply_query_params(&mut url, &plan.query_params);

    let mut request = client
        .request(plan.method.clone(), url)
        .headers(plan.headers.clone());
    if let Some(body) = &plan.body {
        request = apply_body(request, &plan.headers, plan.body_format, body);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            RawSample {
                index,
                status: Some(status),
                latency_ms: started.elapsed().as_millis() as u64,
                epoch_secs,
                candidates: extract_candidates(&headers, &body, plan),
                error: None,
            }
        }
        Err(error) => RawSample {
            index,
            status: None,
            latency_ms: started.elapsed().as_millis() as u64,
            epoch_secs,
            candidates: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

fn extract_candidates(headers: &HeaderMap, body: &str, plan: &ScanPlan) -> Vec<TokenCandidate> {
    let mut candidates = Vec::new();

    if matches!(
        plan.token_location,
        TokenLocation::Auto | TokenLocation::SetCookie
    ) {
        for value in headers.get_all(SET_COOKIE) {
            if let Ok(value) = value.to_str()
                && let Some((name, token)) = parse_set_cookie(value)
                && token_name_matches(plan.token_name.as_deref(), &name)
            {
                candidates.push(TokenCandidate {
                    source: TokenSource::SetCookie,
                    name,
                    value: token,
                });
            }
        }
    }

    if matches!(
        plan.token_location,
        TokenLocation::Auto | TokenLocation::Body
    ) && let Some(name) = plan.token_name.as_deref()
        && let Some(token) = extract_named_body_token(body, name)
    {
        candidates.push(TokenCandidate {
            source: TokenSource::Body,
            name: name.to_owned(),
            value: token,
        });
    }

    candidates
}

fn parse_set_cookie(value: &str) -> Option<(String, String)> {
    let pair = value.split(';').next()?.trim();
    let (name, token) = pair.split_once('=')?;
    let name = name.trim();
    let token = token.trim();
    if name.is_empty() || token.is_empty() {
        return None;
    }
    Some((name.to_owned(), token.to_owned()))
}

fn token_name_matches(expected: Option<&str>, actual: &str) -> bool {
    expected
        .map(|expected| expected.eq_ignore_ascii_case(actual))
        .unwrap_or(true)
}

fn extract_named_body_token(body: &str, name: &str) -> Option<String> {
    extract_query_style_token(body, name)
        .or_else(|| extract_json_style_token(body, name))
        .or_else(|| extract_html_input_token(body, name))
}

fn extract_query_style_token(body: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=");
    let start = body.find(&marker)? + marker.len();
    let token = body[start..]
        .split(|ch: char| ch == '&' || ch == '"' || ch == '\'' || ch.is_whitespace())
        .next()?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn extract_json_style_token(body: &str, name: &str) -> Option<String> {
    let marker = format!("\"{name}\"");
    let start = body.find(&marker)? + marker.len();
    let after_colon = body[start..].find(':')? + start + 1;
    let value = body[after_colon..].trim_start();
    let value = value.strip_prefix('"')?;
    let token = value.split('"').next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn extract_html_input_token(body: &str, name: &str) -> Option<String> {
    let name_marker = format!("name=\"{name}\"");
    let start = body.find(&name_marker)?;
    let value_marker = "value=\"";
    let value_start = body[start..].find(value_marker)? + start + value_marker.len();
    let token = body[value_start..].split('"').next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn apply_body(
    request: reqwest::RequestBuilder,
    headers: &HeaderMap,
    body_format: BodyFormat,
    body: &Value,
) -> reqwest::RequestBuilder {
    match resolve_body_format(headers, body_format, body) {
        BodyFormat::Form => {
            if let Some(fields) = form_fields(body) {
                request.form(&fields)
            } else {
                request.json(body)
            }
        }
        BodyFormat::Json => request.json(body),
        BodyFormat::Auto => match body {
            Value::String(value) => request.body(value.to_owned()),
            _ => request.json(body),
        },
    }
}

fn resolve_body_format(headers: &HeaderMap, body_format: BodyFormat, body: &Value) -> BodyFormat {
    match body_format {
        BodyFormat::Json | BodyFormat::Form => body_format,
        BodyFormat::Auto => {
            if content_type_contains(headers, "application/json") {
                BodyFormat::Json
            } else if content_type_contains(headers, "application/x-www-form-urlencoded") {
                BodyFormat::Form
            } else if form_fields(body).is_some() {
                BodyFormat::Form
            } else {
                BodyFormat::Json
            }
        }
    }
}

fn content_type_contains(headers: &HeaderMap, needle: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains(needle))
        .unwrap_or(false)
}

fn form_fields(body: &Value) -> Option<Vec<(String, String)>> {
    let Value::Object(map) = body else {
        return None;
    };
    let mut fields = Vec::with_capacity(map.len());
    for (name, value) in map {
        fields.push((name.to_owned(), scalar_value_to_string(value)?));
    }
    Some(fields)
}

fn scalar_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
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

#[derive(Debug, Clone)]
struct RawSample {
    index: u64,
    status: Option<u16>,
    latency_ms: u64,
    epoch_secs: u64,
    candidates: Vec<TokenCandidate>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct TokenCandidate {
    source: TokenSource,
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenSource {
    SetCookie,
    Body,
}

impl TokenSource {
    fn as_str(self) -> &'static str {
        match self {
            TokenSource::SetCookie => "set_cookie",
            TokenSource::Body => "body",
        }
    }
}

#[derive(Debug, Clone, Eq)]
struct CandidateKey {
    source: TokenSource,
    name: String,
}

impl PartialEq for CandidateKey {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.name.eq_ignore_ascii_case(&other.name)
    }
}

impl Hash for CandidateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.source.hash(state);
        self.name.to_ascii_lowercase().hash(state);
    }
}

#[derive(Debug, Clone)]
struct SelectedTokenSample {
    index: u64,
    status: Option<u16>,
    latency_ms: u64,
    epoch_secs: u64,
    token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WeakSessionIdReport {
    url: String,
    method: String,
    token_name: Option<String>,
    token_source: Option<String>,
    requested_samples: u64,
    collected_samples: usize,
    unique_token_count: usize,
    duplicate_token_count: usize,
    risk_level: String,
    summary: String,
    sample_coverage: Vec<String>,
    attack_types: Vec<String>,
    remediation: Vec<String>,
    observations: WeakSessionObservation,
    issues: Vec<WeakSessionIssue>,
    samples: Vec<RedactedTokenSample>,
    recommendations: Vec<String>,
}

impl WeakSessionIdReport {
    fn from_samples(plan: ScanPlan, raw_samples: Vec<RawSample>) -> Self {
        let selected_key = select_candidate_key(&plan, &raw_samples);
        let selected_samples = selected_token_samples(&raw_samples, selected_key.as_ref());
        let values = selected_samples
            .iter()
            .filter_map(|sample| sample.token.as_ref())
            .cloned()
            .collect::<Vec<_>>();
        let unique_token_count = values.iter().collect::<HashSet<_>>().len();
        let duplicate_token_count = values.len().saturating_sub(unique_token_count);
        let observations = WeakSessionObservation::from_values(&values);
        let issues = issues_from_samples(&selected_samples, selected_key.as_ref(), &observations);
        let risk_level = aggregate_risk(&issues).to_owned();
        let issue_count = issues
            .iter()
            .filter(|issue| issue.severity != "info")
            .count();
        let token_name = selected_key.as_ref().map(|key| key.name.clone());
        let token_source = selected_key
            .as_ref()
            .map(|key| key.source.as_str().to_owned());
        let summary = weak_session_summary(
            &risk_level,
            plan.sample_count,
            values.len(),
            unique_token_count,
            duplicate_token_count,
            issue_count,
            &issues,
        );
        let sample_coverage = weak_session_sample_coverage(&plan, &selected_samples, &values);
        let attack_types = weak_session_attack_types(&issues);
        let remediation = weak_session_remediation(&issues);

        Self {
            url: plan.url.to_string(),
            method: plan.method.to_string(),
            token_name,
            token_source,
            requested_samples: plan.sample_count,
            collected_samples: values.len(),
            unique_token_count,
            duplicate_token_count,
            risk_level,
            summary,
            sample_coverage,
            attack_types,
            remediation,
            observations,
            issues,
            samples: selected_samples
                .iter()
                .map(RedactedTokenSample::from_sample)
                .collect(),
            recommendations: recommendations(),
        }
    }

    fn summary(&self) -> String {
        self.summary.clone()
    }
}

#[derive(Debug, Serialize)]
struct WeakSessionObservation {
    token_lengths: Vec<usize>,
    character_sets: Vec<String>,
    all_numeric: bool,
    all_hex: bool,
    average_estimated_entropy_bits: f64,
}

impl WeakSessionObservation {
    fn from_values(values: &[String]) -> Self {
        let token_lengths = sorted_unique(values.iter().map(|value| value.len()));
        let character_sets = sorted_unique(values.iter().map(|value| charset_label(value)));
        let all_numeric =
            !values.is_empty() && values.iter().all(|value| value.parse::<u128>().is_ok());
        let all_hex = !values.is_empty() && values.iter().all(|value| is_hex(value));
        let average_estimated_entropy_bits = if values.is_empty() {
            0.0
        } else {
            values
                .iter()
                .map(|value| estimated_entropy_bits(value))
                .sum::<f64>()
                / values.len() as f64
        };

        Self {
            token_lengths,
            character_sets,
            all_numeric,
            all_hex,
            average_estimated_entropy_bits,
        }
    }
}

#[derive(Debug, Serialize)]
struct WeakSessionIssue {
    title: String,
    severity: String,
    category: String,
    evidence: Vec<String>,
    impact: String,
    recommendation: String,
}

#[derive(Debug, Serialize)]
struct RedactedTokenSample {
    index: u64,
    status: Option<u16>,
    latency_ms: u64,
    epoch_secs: u64,
    token_preview: Option<String>,
    token_len: Option<usize>,
    error: Option<String>,
}

impl RedactedTokenSample {
    fn from_sample(sample: &SelectedTokenSample) -> Self {
        Self {
            index: sample.index,
            status: sample.status,
            latency_ms: sample.latency_ms,
            epoch_secs: sample.epoch_secs,
            token_preview: sample.token.as_deref().map(mask_token),
            token_len: sample.token.as_ref().map(String::len),
            error: sample.error.clone(),
        }
    }
}

fn select_candidate_key(plan: &ScanPlan, samples: &[RawSample]) -> Option<CandidateKey> {
    let mut groups: HashMap<CandidateKey, Vec<String>> = HashMap::new();
    for sample in samples {
        for candidate in &sample.candidates {
            if !location_matches(plan.token_location, candidate.source) {
                continue;
            }
            if !token_name_matches(plan.token_name.as_deref(), &candidate.name) {
                continue;
            }
            groups
                .entry(CandidateKey {
                    source: candidate.source,
                    name: candidate.name.clone(),
                })
                .or_default()
                .push(candidate.value.clone());
        }
    }

    groups
        .into_iter()
        .max_by_key(|(key, values)| candidate_score(key, values))
        .map(|(key, _)| key)
}

fn candidate_score(key: &CandidateKey, values: &[String]) -> usize {
    let unique_count = values.iter().collect::<HashSet<_>>().len();
    let changing_bonus = usize::from(unique_count > 1) * 25;
    let ignored_penalty = usize::from(is_static_lab_cookie(&key.name)) * 20;
    values.len() * 10 + unique_count * 8 + changing_bonus.saturating_sub(ignored_penalty)
}

fn is_static_lab_cookie(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "security" | "locale")
}

fn location_matches(location: TokenLocation, source: TokenSource) -> bool {
    match location {
        TokenLocation::Auto => true,
        TokenLocation::SetCookie => source == TokenSource::SetCookie,
        TokenLocation::Body => source == TokenSource::Body,
    }
}

fn selected_token_samples(
    raw_samples: &[RawSample],
    key: Option<&CandidateKey>,
) -> Vec<SelectedTokenSample> {
    raw_samples
        .iter()
        .map(|sample| {
            let token = key.and_then(|key| {
                sample
                    .candidates
                    .iter()
                    .find(|candidate| {
                        candidate.source == key.source
                            && candidate.name.eq_ignore_ascii_case(&key.name)
                    })
                    .map(|candidate| candidate.value.clone())
            });

            SelectedTokenSample {
                index: sample.index,
                status: sample.status,
                latency_ms: sample.latency_ms,
                epoch_secs: sample.epoch_secs,
                token,
                error: sample.error.clone(),
            }
        })
        .collect()
}

fn issues_from_samples(
    samples: &[SelectedTokenSample],
    selected_key: Option<&CandidateKey>,
    observations: &WeakSessionObservation,
) -> Vec<WeakSessionIssue> {
    let values_with_time = samples
        .iter()
        .filter_map(|sample| {
            sample
                .token
                .as_ref()
                .map(|token| (sample.index, token.as_str(), sample.epoch_secs))
        })
        .collect::<Vec<_>>();
    let values = values_with_time
        .iter()
        .map(|(_, value, _)| *value)
        .collect::<Vec<_>>();

    if selected_key.is_none() || values.is_empty() {
        return vec![WeakSessionIssue {
            title: "No generated session ID was observed".to_owned(),
            severity: "unknown".to_owned(),
            category: "scan_coverage".to_owned(),
            evidence: vec![
                "No matching Set-Cookie or configured body token was found in the sampled responses."
                    .to_owned(),
            ],
            impact: "The scanner could not assess session ID predictability without an observable token."
                .to_owned(),
            recommendation:
                "Provide token_name, token_location, authenticated Cookie headers, or the endpoint that actually generates the session ID."
                    .to_owned(),
        }];
    }

    let mut issues = Vec::new();
    push_duplicate_issue(&mut issues, &values);
    push_sequential_numeric_issue(&mut issues, &values);
    push_timestamp_issue(&mut issues, &values_with_time);
    push_md5_timestamp_issue(&mut issues, &values_with_time);
    push_low_entropy_issue(&mut issues, observations);

    if issues.is_empty() {
        issues.push(WeakSessionIssue {
            title: "No obvious weak session ID pattern detected".to_owned(),
            severity: "info".to_owned(),
            category: "session_id_quality".to_owned(),
            evidence: vec![format!(
                "{} sampled token(s), {} unique token(s), average estimated entropy {:.1} bits.",
                values.len(),
                values.iter().collect::<HashSet<_>>().len(),
                observations.average_estimated_entropy_bits
            )],
            impact: "The sampled IDs did not show duplicate, sequential, timestamp, or low-entropy patterns in this lightweight check.".to_owned(),
            recommendation: "Keep using cryptographically secure random session IDs and re-test after authentication/session changes.".to_owned(),
        });
    }

    issues
}

fn push_duplicate_issue(issues: &mut Vec<WeakSessionIssue>, values: &[&str]) {
    let unique = values.iter().collect::<HashSet<_>>().len();
    let duplicate_count = values.len().saturating_sub(unique);
    if duplicate_count == 0 {
        return;
    }

    issues.push(WeakSessionIssue {
        title: "Duplicate session IDs observed".to_owned(),
        severity: "high".to_owned(),
        category: "session_id_predictability".to_owned(),
        evidence: vec![format!(
            "{duplicate_count} duplicate token occurrence(s) across {} collected sample(s).",
            values.len()
        )],
        impact: "A generated session ID repeated during sampling, which can allow session collision or prediction in weak generators.".to_owned(),
        recommendation: "Generate every session ID with a cryptographically secure random generator and enough entropy."
            .to_owned(),
    });
}

fn push_sequential_numeric_issue(issues: &mut Vec<WeakSessionIssue>, values: &[&str]) {
    if values.len() < 3 {
        return;
    }
    let Some(numbers) = parse_u128_values(values) else {
        return;
    };
    if !is_strictly_increasing(&numbers) {
        return;
    }

    let deltas = numbers
        .windows(2)
        .map(|window| window[1].saturating_sub(window[0]))
        .collect::<Vec<_>>();
    let constant_step = deltas.iter().all(|delta| *delta == deltas[0]);
    if constant_step || deltas.iter().all(|delta| *delta <= 10) {
        issues.push(WeakSessionIssue {
            title: "Sequential numeric session IDs".to_owned(),
            severity: "high".to_owned(),
            category: "session_id_predictability".to_owned(),
            evidence: vec![format!(
                "Numeric tokens increased monotonically; observed step pattern: {:?}.",
                deltas
            )],
            impact:
                "Sequential session IDs are directly guessable and can enable session prediction."
                    .to_owned(),
            recommendation:
                "Replace numeric counters with at least 128 bits of CSPRNG-backed randomness."
                    .to_owned(),
        });
    }
}

fn push_timestamp_issue(issues: &mut Vec<WeakSessionIssue>, values: &[(u64, &str, u64)]) {
    let matches = values
        .iter()
        .filter(|(_, value, epoch_secs)| looks_like_epoch_timestamp(value, *epoch_secs))
        .count();
    if matches < required_majority(values.len()) {
        return;
    }

    issues.push(WeakSessionIssue {
        title: "Session IDs look timestamp-based".to_owned(),
        severity: "high".to_owned(),
        category: "session_id_predictability".to_owned(),
        evidence: vec![format!(
            "{matches}/{} token(s) matched nearby Unix timestamp seconds or milliseconds.",
            values.len()
        )],
        impact: "Timestamp-derived session IDs are predictable within a small time window."
            .to_owned(),
        recommendation: "Do not derive session IDs from time. Use CSPRNG-backed random bytes."
            .to_owned(),
    });
}

fn push_md5_timestamp_issue(issues: &mut Vec<WeakSessionIssue>, values: &[(u64, &str, u64)]) {
    let matches = values
        .iter()
        .filter(|(_, value, epoch_secs)| md5_of_nearby_epoch_matches(value, *epoch_secs))
        .count();
    if matches < required_majority(values.len()) {
        return;
    }

    issues.push(WeakSessionIssue {
        title: "Session IDs match MD5 of nearby Unix timestamps".to_owned(),
        severity: "high".to_owned(),
        category: "session_id_predictability".to_owned(),
        evidence: vec![format!(
            "{matches}/{} token(s) matched md5(time) within +/- {EPOCH_MATCH_WINDOW_SECS}s.",
            values.len()
        )],
        impact: "Hashing the current time hides the timestamp visually but remains predictable."
            .to_owned(),
        recommendation: "Use CSPRNG-backed random session IDs instead of hashing timestamps."
            .to_owned(),
    });
}

fn push_low_entropy_issue(
    issues: &mut Vec<WeakSessionIssue>,
    observations: &WeakSessionObservation,
) {
    if observations.average_estimated_entropy_bits <= 0.0 {
        return;
    }
    let min_len = observations
        .token_lengths
        .iter()
        .min()
        .copied()
        .unwrap_or(0);
    if observations.average_estimated_entropy_bits < 40.0 || min_len < 8 {
        issues.push(WeakSessionIssue {
            title: "Very low estimated session ID entropy".to_owned(),
            severity: "high".to_owned(),
            category: "session_id_entropy".to_owned(),
            evidence: vec![format!(
                "Average estimated token entropy is {:.1} bits; observed lengths: {:?}.",
                observations.average_estimated_entropy_bits, observations.token_lengths
            )],
            impact: "Low-entropy IDs can be guessed or brute-forced more easily.".to_owned(),
            recommendation:
                "Use at least 128 bits of randomness encoded with a sufficiently long token."
                    .to_owned(),
        });
    } else if observations.average_estimated_entropy_bits < 64.0 || min_len < 16 {
        issues.push(WeakSessionIssue {
            title: "Low estimated session ID entropy".to_owned(),
            severity: "medium".to_owned(),
            category: "session_id_entropy".to_owned(),
            evidence: vec![format!(
                "Average estimated token entropy is {:.1} bits; observed lengths: {:?}.",
                observations.average_estimated_entropy_bits, observations.token_lengths
            )],
            impact: "The sampled IDs may not provide enough unpredictability for session tokens."
                .to_owned(),
            recommendation: "Prefer at least 128 bits of CSPRNG-backed randomness for session IDs."
                .to_owned(),
        });
    }
}

fn parse_u128_values(values: &[&str]) -> Option<Vec<u128>> {
    values
        .iter()
        .map(|value| value.parse::<u128>().ok())
        .collect()
}

fn is_strictly_increasing(numbers: &[u128]) -> bool {
    numbers.windows(2).all(|window| window[1] > window[0])
}

fn looks_like_epoch_timestamp(value: &str, sample_epoch_secs: u64) -> bool {
    let Ok(number) = value.parse::<u128>() else {
        return false;
    };
    let seconds = if value.len() >= 13 {
        (number / 1000) as u64
    } else if value.len() == 10 {
        number as u64
    } else {
        return false;
    };
    seconds.abs_diff(sample_epoch_secs) <= TIMESTAMP_NEAR_NOW_SECS
}

fn md5_of_nearby_epoch_matches(value: &str, sample_epoch_secs: u64) -> bool {
    if value.len() != 32 || !is_hex(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let start = sample_epoch_secs.saturating_sub(EPOCH_MATCH_WINDOW_SECS);
    let end = sample_epoch_secs + EPOCH_MATCH_WINDOW_SECS;
    (start..=end).any(|epoch| format!("{:x}", md5::compute(epoch.to_string())) == lower)
}

fn required_majority(len: usize) -> usize {
    if len <= 2 { len } else { (len / 2) + 1 }
}

fn aggregate_risk(issues: &[WeakSessionIssue]) -> &'static str {
    if issues.iter().any(|issue| issue.severity == "high") {
        "high"
    } else if issues.iter().any(|issue| issue.severity == "medium") {
        "medium"
    } else if issues.iter().any(|issue| issue.severity == "unknown") {
        "unknown"
    } else {
        "low"
    }
}

fn weak_session_summary(
    risk_level: &str,
    requested_samples: u64,
    collected_samples: usize,
    unique_count: usize,
    duplicate_count: usize,
    issue_count: usize,
    issues: &[WeakSessionIssue],
) -> String {
    if issue_count == 0 {
        return format!(
            "Weak session ID scan completed: {collected_samples}/{requested_samples} token sample(s), {unique_count} unique, no concrete weak ID issue detected, overall risk {risk_level}."
        );
    }

    let issue_titles = issues
        .iter()
        .filter(|issue| issue.severity != "info")
        .map(|issue| issue.title.as_str())
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        "Weak session ID scan completed: {collected_samples}/{requested_samples} token sample(s), {unique_count} unique, {duplicate_count} duplicate occurrence(s), {issue_count} issue(s), overall risk {risk_level}. Issues: {issue_titles}."
    )
}

fn weak_session_sample_coverage(
    plan: &ScanPlan,
    samples: &[SelectedTokenSample],
    values: &[String],
) -> Vec<String> {
    let observed = values.len();
    let unique = values.iter().collect::<HashSet<_>>().len();
    vec![
        format!("Sampled endpoint: {} {}", plan.method, plan.url),
        format!(
            "Requested {} sample(s), observed {observed} token sample(s).",
            plan.sample_count
        ),
        format!("Observed {unique} unique token value(s)."),
        format!(
            "Token source mode: {}, token name filter: {}.",
            token_location_label(plan.token_location),
            plan.token_name.as_deref().unwrap_or("<auto>")
        ),
        format!(
            "Sampling interval: {} ms, request errors: {}.",
            plan.interval_ms,
            samples
                .iter()
                .filter(|sample| sample.error.is_some())
                .count()
        ),
    ]
}

fn weak_session_attack_types(issues: &[WeakSessionIssue]) -> Vec<String> {
    let mut attack_types = Vec::new();
    for issue in issues {
        match issue.title.as_str() {
            "Duplicate session IDs observed" => {
                push_unique_string(&mut attack_types, "session collision / token reuse")
            }
            "Sequential numeric session IDs" => {
                push_unique_string(&mut attack_types, "sequential session prediction")
            }
            "Session IDs look timestamp-based" => {
                push_unique_string(&mut attack_types, "timestamp-based session prediction")
            }
            title if title.contains("MD5 of nearby Unix timestamps") => {
                push_unique_string(&mut attack_types, "md5(time) session prediction")
            }
            title if title.contains("entropy") => {
                push_unique_string(&mut attack_types, "low-entropy session guessing")
            }
            "No generated session ID was observed" => {
                push_unique_string(&mut attack_types, "scan coverage validation")
            }
            _ => push_unique_string(&mut attack_types, &issue.category),
        }
    }
    if attack_types.is_empty() {
        attack_types.push("weak session ID generation".to_owned());
    }
    attack_types
}

fn weak_session_remediation(issues: &[WeakSessionIssue]) -> Vec<String> {
    let mut remediation = Vec::new();
    for issue in issues {
        push_unique_string(&mut remediation, &issue.recommendation);
    }
    for recommendation in recommendations() {
        push_unique_string(&mut remediation, &recommendation);
    }
    remediation
}

fn token_location_label(location: TokenLocation) -> &'static str {
    match location {
        TokenLocation::Auto => "auto",
        TokenLocation::SetCookie => "set_cookie",
        TokenLocation::Body => "body",
    }
}

fn recommendations() -> Vec<String> {
    vec![
        "Generate session IDs with a cryptographically secure random number generator."
            .to_owned(),
        "Use at least 128 bits of entropy for session identifiers.".to_owned(),
        "Do not derive session IDs from counters, timestamps, request order, or hashes of predictable values."
            .to_owned(),
        "Rotate session IDs after login and privilege changes.".to_owned(),
    ]
}

fn sorted_unique<T>(values: impl Iterator<Item = T>) -> Vec<T>
where
    T: Ord,
{
    let mut values = values.collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn push_unique_string(items: &mut Vec<String>, item: &str) {
    if !item.is_empty() && !items.iter().any(|existing| existing == item) {
        items.push(item.to_owned());
    }
}

fn charset_label(value: &str) -> String {
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        "numeric".to_owned()
    } else if is_hex(value) {
        "hex".to_owned()
    } else if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        "base64url_or_alnum".to_owned()
    } else {
        "mixed".to_owned()
    }
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn estimated_entropy_bits(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::<char, usize>::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let len = value.chars().count() as f64;
    let entropy_per_char = counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>();
    entropy_per_char * len
}

fn mask_token(value: &str) -> String {
    let len = value.chars().count();
    if len <= 6 {
        return "***".to_owned();
    }
    let start = value.chars().take(3).collect::<String>();
    let end = value
        .chars()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{start}...{end}")
}

fn emit_progress(
    progress: Option<&ToolProgressCallback>,
    completed: u64,
    total: u64,
    observed_tokens: u64,
) {
    let Some(progress) = progress else {
        return;
    };
    progress(
        ToolProgress::new(
            "weak_session_id_scan",
            format!(
                "{completed}/{total} samples collected, {observed_tokens} with token candidates"
            ),
            completed,
            total,
        )
        .with_metadata(json!({
            "display_type": "percent",
            "completed_samples": completed,
            "sample_count": total,
            "observed_token_samples": observed_tokens
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

fn default_sample_count() -> u64 {
    DEFAULT_SAMPLE_COUNT
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolRegistry;

    #[test]
    fn parses_set_cookie_values() {
        assert_eq!(
            parse_set_cookie("dvwaSession=123; path=/; HttpOnly"),
            Some(("dvwaSession".to_owned(), "123".to_owned()))
        );
    }

    #[test]
    fn detects_sequential_numeric_session_ids() {
        let samples = selected_samples_from_values(&["1", "2", "3", "4"], 1_700_000_000);
        let observations = WeakSessionObservation::from_values(
            &samples
                .iter()
                .filter_map(|sample| sample.token.clone())
                .collect::<Vec<_>>(),
        );
        let issues = issues_from_samples(
            &samples,
            Some(&CandidateKey {
                source: TokenSource::SetCookie,
                name: "dvwaSession".to_owned(),
            }),
            &observations,
        );

        assert!(issues.iter().any(
            |issue| issue.title == "Sequential numeric session IDs" && issue.severity == "high"
        ));
    }

    #[test]
    fn detects_timestamp_session_ids() {
        let epoch = 1_700_000_000;
        let values = [
            epoch.to_string(),
            (epoch + 1).to_string(),
            (epoch + 2).to_string(),
        ];
        let samples = selected_samples_from_values(
            &values.iter().map(String::as_str).collect::<Vec<_>>(),
            epoch,
        );
        let observations = WeakSessionObservation::from_values(&values.to_vec());
        let issues = issues_from_samples(
            &samples,
            Some(&CandidateKey {
                source: TokenSource::SetCookie,
                name: "dvwaSession".to_owned(),
            }),
            &observations,
        );

        assert!(
            issues
                .iter()
                .any(|issue| issue.title == "Session IDs look timestamp-based"
                    && issue.severity == "high")
        );
    }

    #[test]
    fn detects_md5_of_timestamp_session_ids() {
        let epoch = 1_700_000_000;
        let values = [
            format!("{:x}", md5::compute(epoch.to_string())),
            format!("{:x}", md5::compute((epoch + 1).to_string())),
            format!("{:x}", md5::compute((epoch + 2).to_string())),
        ];
        let samples = selected_samples_from_values(
            &values.iter().map(String::as_str).collect::<Vec<_>>(),
            epoch,
        );
        let observations = WeakSessionObservation::from_values(&values.to_vec());
        let issues = issues_from_samples(
            &samples,
            Some(&CandidateKey {
                source: TokenSource::SetCookie,
                name: "dvwaSession".to_owned(),
            }),
            &observations,
        );

        assert!(issues.iter().any(
            |issue| issue.title.contains("MD5 of nearby Unix timestamps")
                && issue.severity == "high"
        ));
    }

    #[test]
    fn masks_token_values_in_report_samples() {
        assert_eq!(mask_token("abcdef123456"), "abc...456");
        assert_eq!(mask_token("abc"), "***");
    }

    #[tokio::test]
    async fn registry_includes_weak_session_id_scan() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("weak_session_id_scan"));
        assert!(registry.spec("weak_session_id_scan").is_some());
    }

    fn selected_samples_from_values(values: &[&str], epoch_secs: u64) -> Vec<SelectedTokenSample> {
        values
            .iter()
            .enumerate()
            .map(|(index, value)| SelectedTokenSample {
                index: index as u64 + 1,
                status: Some(200),
                latency_ms: 10,
                epoch_secs: epoch_secs + index as u64,
                token: Some((*value).to_owned()),
                error: None,
            })
            .collect()
    }
}
