use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
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
const DEFAULT_TIME_CONFIRMATION_RUNS: u64 = 2;
const MAX_TIME_CONFIRMATION_RUNS: u64 = 3;
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
                    "verification_url": {
                        "type": "string",
                        "description": "Optional URL to fetch after each probe request. Use this for stateful lab flows where one endpoint accepts input and another page renders the database-backed result."
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
                        "description": "Optional request body. Object fields can be selected as injectable fields."
                    },
                    "body_format": {
                        "type": "string",
                        "description": "How to send object bodies. Use form for application/x-www-form-urlencoded lab forms such as DVWA medium/high, json for API JSON bodies, or auto to infer from Content-Type and scalar object bodies.",
                        "enum": ["auto", "json", "form"],
                        "default": "auto"
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
                    "confirm_time_based": {
                        "type": "boolean",
                        "description": "Whether to confirm time-delay findings by alternating baseline and delayed probes. This validates blind SQL injection signals without extracting data.",
                        "default": true
                    },
                    "time_confirmation_runs": {
                        "type": "integer",
                        "description": "Number of baseline/delayed confirmation pairs to run after an initial time-delay signal.",
                        "minimum": 1,
                        "maximum": MAX_TIME_CONFIRMATION_RUNS,
                        "default": DEFAULT_TIME_CONFIRMATION_RUNS
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
    #[serde(default)]
    verification_url: Option<String>,
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
    injectable_fields: Option<Vec<String>>,
    #[serde(default = "default_include_time_based")]
    include_time_based: bool,
    #[serde(default = "default_confirm_time_based")]
    confirm_time_based: bool,
    #[serde(default = "default_time_confirmation_runs")]
    time_confirmation_runs: u64,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_time_delay_ms")]
    max_time_delay_ms: u64,
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

#[derive(Clone)]
struct ScanPlan {
    url: Url,
    verification_url: Option<Url>,
    method: Method,
    headers: HeaderMap,
    query_params: HashMap<String, String>,
    body: Option<Value>,
    body_format: BodyFormat,
    fields: Vec<String>,
    include_time_based: bool,
    confirm_time_based: bool,
    time_confirmation_runs: u64,
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
        let verification_url = self
            .verification_url
            .map(|url| Url::parse(&url).map_err(|error| invalid(tool, error.to_string())))
            .transpose()?;
        if let Some(verification_url) = &verification_url {
            match verification_url.scheme() {
                "http" | "https" => {}
                scheme => {
                    return Err(invalid(
                        tool,
                        format!("unsupported verification_url scheme: {scheme}"),
                    ));
                }
            }
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
            verification_url,
            method,
            headers,
            query_params: self.query_params,
            body: self.body,
            body_format: self.body_format,
            fields,
            include_time_based: self.include_time_based,
            confirm_time_based: self.confirm_time_based,
            time_confirmation_runs: bounded(
                tool,
                "time_confirmation_runs",
                self.time_confirmation_runs,
                1,
                MAX_TIME_CONFIRMATION_RUNS,
            )?,
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
    let checklist = scan_checklist(
        &plan.fields,
        plan.include_time_based,
        plan.confirm_time_based,
    );
    let total = checklist.len() as u64;
    let mut completed = 1;
    emit_progress(progress.as_ref(), completed, total, &checklist);

    if plan.fields.is_empty() {
        return DatabaseRiskReport::empty(plan, baseline);
    }

    let mut findings = Vec::new();
    for field in &plan.fields {
        let payloads = payloads_for_field(&plan, field);

        let mut error_probes = Vec::new();
        for payload in payloads.error_payloads {
            error_probes.push(NamedProbeObservation {
                name: payload.name,
                payload: payload.value.clone(),
                observation: send_probe(&client, &plan, Some(field), Some(&payload.value)).await,
            });
        }
        completed += 1;
        emit_progress(progress.as_ref(), completed, total, &checklist);

        let mut boolean_pairs = Vec::new();
        for pair in payloads.boolean_pairs {
            let true_observation =
                send_probe(&client, &plan, Some(field), Some(&pair.true_payload)).await;
            let false_observation =
                send_probe(&client, &plan, Some(field), Some(&pair.false_payload)).await;
            boolean_pairs.push(BooleanProbeObservation {
                name: pair.name,
                true_payload: pair.true_payload,
                false_payload: pair.false_payload,
                true_observation,
                false_observation,
            });
        }
        completed += 2;
        emit_progress(progress.as_ref(), completed.min(total), total, &checklist);

        let mut time_probes = Vec::new();
        let mut time_confirmations = Vec::new();
        if plan.include_time_based {
            for payload in payloads.time_payloads {
                time_probes.push(NamedProbeObservation {
                    name: payload.name,
                    payload: payload.value.clone(),
                    observation: send_probe(&client, &plan, Some(field), Some(&payload.value))
                        .await,
                });
            }
            completed += 1;
            emit_progress(progress.as_ref(), completed.min(total), total, &checklist);

            if plan.confirm_time_based {
                if let Some(candidate) =
                    strongest_time_delay_candidate(&baseline, &time_probes, &plan)
                {
                    time_confirmations = confirm_time_delay(&client, &plan, field, candidate).await;
                }
                completed += 1;
                emit_progress(progress.as_ref(), completed.min(total), total, &checklist);
            }
        }

        findings.push(analyze_field(
            field,
            &baseline,
            &error_probes,
            &boolean_pairs,
            &time_probes,
            &time_confirmations,
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
    let state_response = send_probe_request(client, plan, field, payload).await;
    if let Some(verification_url) = &plan.verification_url {
        if let Some(error) = state_response.error {
            return ProbeObservation {
                status: state_response.status,
                latency_ms: started.elapsed().as_millis() as u64,
                body_len: state_response.body_len,
                body_preview: state_response.body_preview,
                error: Some(format!("state request failed before verification: {error}")),
            };
        }

        return send_verification_request(client, plan, verification_url, started).await;
    }

    state_response
}

async fn send_probe_request(
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
        request = apply_body(request, &plan.headers, plan.body_format, &body);
    }

    observe_response(request.send().await, started).await
}

async fn send_verification_request(
    client: &Client,
    plan: &ScanPlan,
    verification_url: &Url,
    started: tokio::time::Instant,
) -> ProbeObservation {
    let request = client
        .get(verification_url.clone())
        .headers(plan.headers.clone());
    observe_response(request.send().await, started).await
}

async fn observe_response(
    response: std::result::Result<reqwest::Response, reqwest::Error>,
    started: tokio::time::Instant,
) -> ProbeObservation {
    match response {
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
        BodyFormat::Auto | BodyFormat::Json => request.json(body),
    }
}

fn analyze_field(
    field: &str,
    baseline: &ProbeObservation,
    error_probes: &[NamedProbeObservation],
    boolean_pairs: &[BooleanProbeObservation],
    time_probes: &[NamedProbeObservation],
    time_confirmations: &[TimeDelayConfirmation],
    max_time_delay_ms: u64,
) -> FieldFinding {
    let mut signals = Vec::new();

    for error_probe in error_probes {
        if let Some(pattern) = database_error_pattern(&error_probe.observation.body_preview) {
            signals.push(RiskSignal {
                kind: "database_error_leak".to_owned(),
                severity: "high".to_owned(),
                evidence: format!(
                    "{} probe with payload `{}` response contained database error pattern: {pattern}",
                    error_probe.name, error_probe.payload
                ),
            });
        }
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

    if baseline_usable {
        for error_probe in error_probes {
            if status_changed(baseline, &error_probe.observation) {
                signals.push(RiskSignal {
                    kind: "status_change_on_quote".to_owned(),
                    severity: "medium".to_owned(),
                    evidence: format!(
                        "baseline status {:?}, {} probe with payload `{}` status {:?}",
                        baseline.status,
                        error_probe.name,
                        error_probe.payload,
                        error_probe.observation.status
                    ),
                });
            }
        }

        for pair in boolean_pairs {
            if let Some(evidence) = boolean_difference_evidence(baseline, pair) {
                signals.push(RiskSignal {
                    kind: "boolean_response_difference".to_owned(),
                    severity: "medium".to_owned(),
                    evidence,
                });
            }
        }
    }

    if baseline_usable {
        for time_probe in time_probes {
            let delta = time_probe
                .observation
                .latency_ms
                .saturating_sub(baseline.latency_ms);
            if delta >= max_time_delay_ms {
                signals.push(RiskSignal {
                    kind: "time_delay_signal".to_owned(),
                    severity: "medium".to_owned(),
                    evidence: format!(
                        "{} probe with payload `{}` latency {} ms vs baseline {} ms",
                        time_probe.name,
                        time_probe.payload,
                        time_probe.observation.latency_ms,
                        baseline.latency_ms
                    ),
                });
            }
        }
    }

    for confirmation in time_confirmations {
        if confirmation.confirmed {
            signals.push(RiskSignal {
                kind: "time_delay_confirmed".to_owned(),
                severity: "high".to_owned(),
                evidence: confirmation.evidence(),
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
    verification_url: Option<String>,
    method: String,
    body_format: String,
    tested_fields: Vec<String>,
    risk_level: String,
    summary: String,
    sample_coverage: Vec<String>,
    attack_types: Vec<String>,
    remediation: Vec<String>,
    baseline: ProbeSummary,
    findings: Vec<FieldFinding>,
    issues: Vec<DatabaseRiskIssue>,
    recommendations: Vec<String>,
}

impl DatabaseRiskReport {
    fn empty(plan: ScanPlan, baseline: ProbeObservation) -> Self {
        Self {
            url: plan.url.to_string(),
            verification_url: plan.verification_url.map(|url| url.to_string()),
            method: plan.method.to_string(),
            body_format: body_format_label(plan.body_format).to_owned(),
            tested_fields: Vec::new(),
            risk_level: "unknown".to_owned(),
            summary: "No injectable query or body fields were provided or detected.".to_owned(),
            sample_coverage: vec![
                format!("Baseline request: {} {}", plan.method, plan.url),
                "No query parameters, JSON body fields, or injectable_fields were available to mutate.".to_owned(),
            ],
            attack_types: vec!["scan coverage validation".to_owned()],
            remediation: vec![
                "Provide a representative request that includes the database-backed parameter to test.".to_owned(),
                "Include query parameters, JSON body fields, form fields, or injectable_fields.".to_owned(),
            ],
            baseline: ProbeSummary::from_observation(&baseline),
            findings: Vec::new(),
            issues: vec![DatabaseRiskIssue {
                title: "No testable database input point was provided".to_owned(),
                severity: "info".to_owned(),
                category: "scan_coverage".to_owned(),
                affected_fields: Vec::new(),
                evidence: vec![
                    "The request did not contain query parameters, JSON body fields, or injectable_fields."
                        .to_owned(),
                ],
                impact: "The scanner could not exercise parameters that may reach database queries."
                    .to_owned(),
                recommendation:
                    "Provide a representative URL with query parameters, JSON body, or injectable_fields."
                        .to_owned(),
            }],
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
        let issues = issues_from_findings(&findings);
        let issue_count = issues
            .iter()
            .filter(|issue| issue.severity != "info")
            .count();
        let sample_coverage = database_sample_coverage(&plan, &findings);
        let attack_types = database_attack_types(&issues);
        let remediation = database_remediation(&issues, risk_level);
        Self {
            url: plan.url.to_string(),
            verification_url: plan.verification_url.map(|url| url.to_string()),
            method: plan.method.to_string(),
            body_format: body_format_label(plan.body_format).to_owned(),
            tested_fields: plan.fields,
            risk_level: risk_level.to_owned(),
            summary: database_risk_summary(risk_level, risky_fields, issue_count, &issues),
            sample_coverage,
            attack_types,
            remediation,
            baseline: ProbeSummary::from_observation(&baseline),
            findings,
            issues,
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
struct DatabaseRiskIssue {
    title: String,
    severity: String,
    category: String,
    affected_fields: Vec<String>,
    evidence: Vec<String>,
    impact: String,
    recommendation: String,
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

#[derive(Debug)]
struct NamedProbeObservation {
    name: String,
    payload: String,
    observation: ProbeObservation,
}

#[derive(Debug)]
struct BooleanProbeObservation {
    name: String,
    true_payload: String,
    false_payload: String,
    true_observation: ProbeObservation,
    false_observation: ProbeObservation,
}

#[derive(Debug)]
struct TimeDelayConfirmation {
    probe_name: String,
    payload: String,
    runs: Vec<TimeDelayConfirmationRun>,
    confirmed: bool,
}

impl TimeDelayConfirmation {
    fn evidence(&self) -> String {
        let run_summary = self
            .runs
            .iter()
            .enumerate()
            .map(|(index, run)| {
                format!(
                    "run {} baseline {} ms, delayed {} ms, delta {} ms",
                    index + 1,
                    run.baseline_latency_ms,
                    run.delayed_latency_ms,
                    run.delta_ms
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "{} probe with payload `{}` confirmed time delay across {} run(s): {run_summary}",
            self.probe_name,
            self.payload,
            self.runs.len()
        )
    }
}

#[derive(Debug)]
struct TimeDelayConfirmationRun {
    baseline_latency_ms: u64,
    delayed_latency_ms: u64,
    delta_ms: u64,
}

#[derive(Debug)]
struct FieldPayloads {
    error_payloads: Vec<ProbePayload>,
    boolean_pairs: Vec<BooleanPayloadPair>,
    time_payloads: Vec<ProbePayload>,
}

#[derive(Debug)]
struct ProbePayload {
    name: String,
    value: String,
}

#[derive(Debug)]
struct BooleanPayloadPair {
    name: String,
    true_payload: String,
    false_payload: String,
}

fn payloads_for_field(plan: &ScanPlan, field: &str) -> FieldPayloads {
    let base_value = field_value(plan, field).unwrap_or_else(|| "1".to_owned());
    let numeric = looks_numeric(&base_value);
    let sleep_secs = ((plan.max_time_delay_ms + 999) / 1000).clamp(1, 3);

    let mut error_payloads = Vec::new();
    push_probe_payload(
        &mut error_payloads,
        "single_quote",
        format!("{base_value}'"),
    );
    push_probe_payload(
        &mut error_payloads,
        "double_quote",
        format!("{base_value}\""),
    );

    let mut boolean_pairs = Vec::new();
    if numeric {
        push_boolean_pair(
            &mut boolean_pairs,
            "numeric_and",
            format!("{base_value} AND 1=1"),
            format!("{base_value} AND 1=2"),
        );
        push_boolean_pair(
            &mut boolean_pairs,
            "numeric_or",
            format!("{base_value} OR 1=1"),
            format!("{base_value} AND 1=2"),
        );
    }
    push_boolean_pair(
        &mut boolean_pairs,
        "quoted_and",
        format!("{base_value}' AND '1'='1"),
        format!("{base_value}' AND '1'='2"),
    );
    push_boolean_pair(
        &mut boolean_pairs,
        "quoted_comment",
        format!("{base_value}' OR '1'='1'-- "),
        format!("{base_value}' AND '1'='2'-- "),
    );

    let mut time_payloads = Vec::new();
    if numeric {
        push_probe_payload(
            &mut time_payloads,
            "numeric_sleep",
            format!("{base_value} AND SLEEP({sleep_secs})"),
        );
    }
    push_probe_payload(
        &mut time_payloads,
        "quoted_sleep",
        format!("{base_value}' AND SLEEP({sleep_secs})-- "),
    );

    FieldPayloads {
        error_payloads,
        boolean_pairs,
        time_payloads,
    }
}

fn push_probe_payload(payloads: &mut Vec<ProbePayload>, name: impl Into<String>, value: String) {
    if payloads.iter().any(|payload| payload.value == value) {
        return;
    }
    payloads.push(ProbePayload {
        name: name.into(),
        value,
    });
}

fn push_boolean_pair(
    pairs: &mut Vec<BooleanPayloadPair>,
    name: impl Into<String>,
    true_payload: String,
    false_payload: String,
) {
    if pairs
        .iter()
        .any(|pair| pair.true_payload == true_payload && pair.false_payload == false_payload)
    {
        return;
    }
    pairs.push(BooleanPayloadPair {
        name: name.into(),
        true_payload,
        false_payload,
    });
}

fn field_value(plan: &ScanPlan, field: &str) -> Option<String> {
    if let Some(value) = plan
        .body
        .as_ref()
        .and_then(|body| body_field_value(body, field))
    {
        return Some(value);
    }
    if let Some(value) = plan.query_params.get(field) {
        return Some(value.to_owned());
    }
    plan.url
        .query_pairs()
        .find(|(name, _)| name == field)
        .map(|(_, value)| value.to_string())
}

fn body_field_value(body: &Value, field: &str) -> Option<String> {
    let Value::Object(map) = body else {
        return None;
    };
    scalar_value_to_string(map.get(field)?)
}

fn looks_numeric(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.parse::<f64>().is_ok()
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

fn push_unique_string(items: &mut Vec<String>, item: &str) {
    if !item.is_empty() && !items.iter().any(|existing| existing == item) {
        items.push(item.to_owned());
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

fn body_format_label(body_format: BodyFormat) -> &'static str {
    match body_format {
        BodyFormat::Auto => "auto",
        BodyFormat::Json => "json",
        BodyFormat::Form => "form",
    }
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

fn strongest_time_delay_candidate<'a>(
    baseline: &ProbeObservation,
    time_probes: &'a [NamedProbeObservation],
    plan: &ScanPlan,
) -> Option<&'a NamedProbeObservation> {
    time_probes
        .iter()
        .filter(|probe| {
            probe
                .observation
                .latency_ms
                .saturating_sub(baseline.latency_ms)
                >= plan.max_time_delay_ms
        })
        .max_by_key(|probe| {
            probe
                .observation
                .latency_ms
                .saturating_sub(baseline.latency_ms)
        })
}

async fn confirm_time_delay(
    client: &Client,
    plan: &ScanPlan,
    field: &str,
    candidate: &NamedProbeObservation,
) -> Vec<TimeDelayConfirmation> {
    let mut runs = Vec::new();
    for _ in 0..plan.time_confirmation_runs {
        let baseline = send_probe(client, plan, None, None).await;
        let delayed = send_probe(client, plan, Some(field), Some(&candidate.payload)).await;
        runs.push(TimeDelayConfirmationRun {
            baseline_latency_ms: baseline.latency_ms,
            delayed_latency_ms: delayed.latency_ms,
            delta_ms: delayed.latency_ms.saturating_sub(baseline.latency_ms),
        });
    }

    let confirmed_runs = runs
        .iter()
        .filter(|run| run.delta_ms >= plan.max_time_delay_ms)
        .count();
    let required_runs = (runs.len() / 2) + 1;
    vec![TimeDelayConfirmation {
        probe_name: candidate.name.clone(),
        payload: candidate.payload.clone(),
        confirmed: confirmed_runs >= required_runs,
        runs,
    }]
}

fn boolean_difference_evidence(
    baseline: &ProbeObservation,
    pair: &BooleanProbeObservation,
) -> Option<String> {
    let true_false_delta = body_len_delta(&pair.true_observation, &pair.false_observation);
    let true_false_similarity = response_similarity(
        &pair.true_observation.body_preview,
        &pair.false_observation.body_preview,
    );
    let baseline_true_similarity =
        response_similarity(&baseline.body_preview, &pair.true_observation.body_preview);
    let baseline_false_similarity =
        response_similarity(&baseline.body_preview, &pair.false_observation.body_preview);
    let status_changed = pair.true_observation.status != pair.false_observation.status;
    let lab_marker_difference = known_sqli_result_marker_difference(
        &pair.true_observation.body_preview,
        &pair.false_observation.body_preview,
    );
    let baseline_aligned_true =
        baseline_true_similarity >= 0.96 && baseline_false_similarity <= 0.93;

    if status_changed
        || true_false_delta > 0.08
        || true_false_similarity <= 0.94
        || baseline_aligned_true
        || lab_marker_difference
    {
        return Some(format!(
            "{} probes differed: true payload `{}`, false payload `{}`, statuses {:?}/{:?}, body lengths {}/{}, true/false similarity {:.3}, baseline true/false similarity {:.3}/{:.3}",
            pair.name,
            pair.true_payload,
            pair.false_payload,
            pair.true_observation.status,
            pair.false_observation.status,
            pair.true_observation.body_len,
            pair.false_observation.body_len,
            true_false_similarity,
            baseline_true_similarity,
            baseline_false_similarity
        ));
    }

    None
}

fn response_similarity(left: &str, right: &str) -> f64 {
    let left = normalized_response_tokens(left);
    let right = normalized_response_tokens(right);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }

    let mut common = 0usize;
    let mut right_counts = HashMap::<&str, usize>::new();
    for token in &right {
        *right_counts.entry(token.as_str()).or_insert(0) += 1;
    }
    for token in &left {
        if let Some(count) = right_counts.get_mut(token.as_str())
            && *count > 0
        {
            common += 1;
            *count -= 1;
        }
    }

    (2 * common) as f64 / (left.len() + right.len()) as f64
}

fn normalized_response_tokens(text: &str) -> Vec<String> {
    strip_html_tags(text)
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

fn strip_html_tags(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_tag = false;
    for ch in text.chars() {
        match ch {
            '<' => {
                in_tag = true;
                output.push(' ');
            }
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
}

fn known_sqli_result_marker_difference(true_body: &str, false_body: &str) -> bool {
    let true_body = true_body.to_ascii_lowercase();
    let false_body = false_body.to_ascii_lowercase();
    let true_has_result = true_body.contains("first name")
        || true_body.contains("surname")
        || true_body.contains("user id");
    let false_has_missing = false_body.contains("missing from the database")
        || false_body.contains("does not exist")
        || false_body.contains("no results");

    (true_has_result && false_has_missing)
        || (true_body.contains("first name") != false_body.contains("first name"))
        || (true_body.contains("surname") != false_body.contains("surname"))
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

fn database_risk_summary(
    risk_level: &str,
    risky_fields: usize,
    issue_count: usize,
    issues: &[DatabaseRiskIssue],
) -> String {
    if issue_count == 0 {
        return format!(
            "Database attack surface scan completed: {risky_fields} risky field(s), no concrete database risk issues detected, overall risk {risk_level}."
        );
    }

    let issue_titles = issues
        .iter()
        .filter(|issue| issue.severity != "info")
        .map(|issue| {
            if issue.affected_fields.is_empty() {
                issue.title.clone()
            } else {
                format!("{} ({})", issue.title, issue.affected_fields.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        "Database attack surface scan completed: {risky_fields} risky field(s), {issue_count} issue(s), overall risk {risk_level}. Issues: {issue_titles}."
    )
}

fn issues_from_findings(findings: &[FieldFinding]) -> Vec<DatabaseRiskIssue> {
    let mut issues = Vec::new();

    push_issue_for_signal(
        &mut issues,
        findings,
        "database_error_leak",
        "SQL/database error information disclosure",
        "high",
        "information_disclosure",
        "The endpoint returned database error text when a quote payload was submitted. This leaks implementation details and often indicates unsafe query construction.",
        "Return generic application errors, log database errors server-side only, and verify all database access uses bind parameters.",
    );

    push_injection_surface_issue(&mut issues, findings);

    push_issue_for_signal(
        &mut issues,
        findings,
        "boolean_response_difference",
        "Boolean-condition response difference",
        "medium",
        "sql_injection_signal",
        "True and false condition payloads produced materially different responses. This can be a SQL injection signal if the field reaches a query predicate.",
        "Review the flagged query path and add regression tests for boolean SQL injection payloads.",
    );

    push_issue_for_signal(
        &mut issues,
        findings,
        "time_delay_confirmed",
        "Time-based SQL injection confirmed",
        "high",
        "sql_injection",
        "Repeated baseline/delayed probe pairs confirmed that a user-controlled field can trigger database time delay behavior.",
        "Treat this as exploitable SQL injection: parameterize the affected query, add strict type validation, and verify the fix with the same confirmation probes.",
    );

    let has_confirmed_time_delay = !fields_with_signal(findings, "time_delay_confirmed").is_empty();
    if !has_confirmed_time_delay {
        push_issue_for_signal(
            &mut issues,
            findings,
            "time_delay_signal",
            "Time-delay response signal",
            "medium",
            "sql_injection_signal",
            "A time-delay payload caused a noticeably slower response than the baseline. This can indicate time-based SQL injection behavior.",
            "Use parameterized queries and verify the database layer does not execute user-controlled expressions.",
        );
    }

    push_issue_for_signal(
        &mut issues,
        findings,
        "status_change_on_quote",
        "Quote payload changed HTTP status",
        "medium",
        "input_handling",
        "A quote payload changed the response status compared with the baseline. This suggests fragile input handling and may hide database errors behind generic 5xx responses.",
        "Validate input types before database access and normalize error handling for malformed parameters.",
    );

    push_issue_for_signal(
        &mut issues,
        findings,
        "baseline_unavailable",
        "Baseline request was not usable",
        "info",
        "scan_coverage",
        "The baseline request failed or returned a server error, so some comparisons may be inconclusive.",
        "Re-run the scan with a known-good authenticated request and representative baseline parameters.",
    );

    issues
}

fn push_injection_surface_issue(issues: &mut Vec<DatabaseRiskIssue>, findings: &[FieldFinding]) {
    let fields = fields_with_any_signal(
        findings,
        &[
            "database_error_leak",
            "boolean_response_difference",
            "time_delay_confirmed",
            "time_delay_signal",
            "status_change_on_quote",
        ],
    );
    if fields.is_empty() {
        return;
    }

    let severity = if !fields_with_signal(findings, "database_error_leak").is_empty()
        || !fields_with_signal(findings, "time_delay_confirmed").is_empty()
    {
        "high"
    } else {
        "medium"
    };
    let evidence = evidence_for_any_signal(
        findings,
        &[
            "database_error_leak",
            "boolean_response_difference",
            "time_delay_confirmed",
            "time_delay_signal",
            "status_change_on_quote",
        ],
    );

    issues.push(DatabaseRiskIssue {
        title: "Possible SQL injection input point".to_owned(),
        severity: severity.to_owned(),
        category: "sql_injection".to_owned(),
        affected_fields: fields,
        evidence,
        impact: "An attacker may be able to influence database query structure or force backend SQL errors through the affected parameter.".to_owned(),
        recommendation: "Treat the affected field as untrusted input, bind it as a parameter, enforce strict type validation, and inspect the exact database query path.".to_owned(),
    });
}

fn push_issue_for_signal(
    issues: &mut Vec<DatabaseRiskIssue>,
    findings: &[FieldFinding],
    signal_kind: &str,
    title: &str,
    severity: &str,
    category: &str,
    impact: &str,
    recommendation: &str,
) {
    let fields = fields_with_signal(findings, signal_kind);
    if fields.is_empty() {
        return;
    }

    issues.push(DatabaseRiskIssue {
        title: title.to_owned(),
        severity: severity.to_owned(),
        category: category.to_owned(),
        affected_fields: fields,
        evidence: evidence_for_signal(findings, signal_kind),
        impact: impact.to_owned(),
        recommendation: recommendation.to_owned(),
    });
}

fn fields_with_signal(findings: &[FieldFinding], signal_kind: &str) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| {
            finding
                .signals
                .iter()
                .any(|signal| signal.kind == signal_kind)
        })
        .map(|finding| finding.field.clone())
        .collect()
}

fn fields_with_any_signal(findings: &[FieldFinding], signal_kinds: &[&str]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| {
            finding
                .signals
                .iter()
                .any(|signal| signal_kinds.contains(&signal.kind.as_str()))
        })
        .map(|finding| finding.field.clone())
        .collect()
}

fn evidence_for_signal(findings: &[FieldFinding], signal_kind: &str) -> Vec<String> {
    findings
        .iter()
        .flat_map(|finding| {
            finding
                .signals
                .iter()
                .filter(move |signal| signal.kind == signal_kind)
                .map(move |signal| format!("{}: {}", finding.field, signal.evidence))
        })
        .collect()
}

fn evidence_for_any_signal(findings: &[FieldFinding], signal_kinds: &[&str]) -> Vec<String> {
    findings
        .iter()
        .flat_map(|finding| {
            finding
                .signals
                .iter()
                .filter(move |signal| signal_kinds.contains(&signal.kind.as_str()))
                .map(move |signal| format!("{}: {}", finding.field, signal.evidence))
        })
        .collect()
}

fn database_sample_coverage(plan: &ScanPlan, findings: &[FieldFinding]) -> Vec<String> {
    let mut coverage = vec![
        format!("Baseline request: {} {}", plan.method, plan.url),
        format!("Body format: {}", body_format_label(plan.body_format)),
        format!(
            "Tested {} field(s): {}",
            plan.fields.len(),
            if plan.fields.is_empty() {
                "<none>".to_owned()
            } else {
                plan.fields.join(", ")
            }
        ),
        "For each field, exercised quote/error probes and boolean true/false probes.".to_owned(),
    ];
    if let Some(verification_url) = &plan.verification_url {
        coverage.push(format!(
            "Stateful verification page fetched after each probe: {verification_url}"
        ));
    }
    if plan.include_time_based {
        coverage.push(format!(
            "Included time-delay probes with threshold {} ms.",
            plan.max_time_delay_ms
        ));
        if plan.confirm_time_based {
            coverage.push(format!(
                "Confirmed time-delay findings with {} baseline/delayed pair(s).",
                plan.time_confirmation_runs
            ));
        }
    }
    for finding in findings {
        coverage.push(format!(
            "Field `{}` produced {} signal(s), field risk {}.",
            finding.field,
            finding.signals.len(),
            finding.risk
        ));
    }
    coverage
}

fn database_attack_types(issues: &[DatabaseRiskIssue]) -> Vec<String> {
    let mut attack_types = Vec::new();
    for issue in issues {
        match issue.category.as_str() {
            "sql_injection" => push_unique_string(&mut attack_types, "SQL injection"),
            "sql_injection_signal" => {
                if issue.title.contains("Time") {
                    push_unique_string(&mut attack_types, "time-based blind SQL injection");
                } else if issue.title.contains("Boolean") {
                    push_unique_string(&mut attack_types, "boolean-based SQL injection");
                } else {
                    push_unique_string(&mut attack_types, "SQL injection signal");
                }
            }
            "information_disclosure" => {
                push_unique_string(&mut attack_types, "database error information disclosure")
            }
            "input_handling" => push_unique_string(&mut attack_types, "malformed input handling"),
            "scan_coverage" => push_unique_string(&mut attack_types, "scan coverage validation"),
            category => push_unique_string(&mut attack_types, category),
        }
    }
    if attack_types.is_empty() {
        attack_types.push("database injection probe".to_owned());
    }
    attack_types
}

fn database_remediation(issues: &[DatabaseRiskIssue], risk_level: &str) -> Vec<String> {
    let mut remediation = Vec::new();
    for issue in issues {
        push_unique_string(&mut remediation, &issue.recommendation);
    }
    for recommendation in recommendations_for(risk_level) {
        push_unique_string(&mut remediation, &recommendation);
    }
    remediation
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

fn scan_checklist(
    fields: &[String],
    include_time_based: bool,
    confirm_time_based: bool,
) -> Vec<String> {
    let mut checklist = vec!["Baseline request".to_owned()];
    for field in fields {
        checklist.push(format!("{field}: quote/error leakage probe"));
        checklist.push(format!("{field}: boolean true probe"));
        checklist.push(format!("{field}: boolean false probe"));
        if include_time_based {
            checklist.push(format!("{field}: time-delay probe"));
            if confirm_time_based {
                checklist.push(format!("{field}: time-delay confirmation"));
            }
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

fn default_confirm_time_based() -> bool {
    true
}

fn default_time_confirmation_runs() -> u64 {
    DEFAULT_TIME_CONFIRMATION_RUNS
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
        let url = Url::parse("https://target.example/search?id=1").expect("url should parse");
        let body = json!({ "name": "alice" });
        let fields = selected_fields(&url, &HashMap::new(), Some(&body), None);

        assert_eq!(fields, vec!["id".to_owned(), "name".to_owned()]);
    }

    #[test]
    fn mutates_query_param_when_body_field_is_absent() {
        let mut url = Url::parse("https://target.example/search?id=1").expect("url should parse");

        upsert_query_param(&mut url, "id", "'");

        assert!(url.as_str().contains("id=%27"));
    }

    #[test]
    fn builds_scan_checklist_for_each_probe() {
        let fields = vec!["date".to_owned()];

        assert_eq!(
            scan_checklist(&fields, true, true),
            vec![
                "Baseline request".to_owned(),
                "date: quote/error leakage probe".to_owned(),
                "date: boolean true probe".to_owned(),
                "date: boolean false probe".to_owned(),
                "date: time-delay probe".to_owned(),
                "date: time-delay confirmation".to_owned(),
            ]
        );
        assert_eq!(scan_checklist(&fields, true, false).len(), 5);
        assert_eq!(scan_checklist(&fields, false, true).len(), 4);
    }

    #[test]
    fn infers_form_body_and_builds_numeric_and_quoted_payloads() {
        let plan = ScanPlan {
            url: Url::parse("https://lab.example/vulnerable/sqli/session-input.php")
                .expect("url should parse"),
            verification_url: Some(
                Url::parse("https://lab.example/vulnerable/sqli/")
                    .expect("verification url should parse"),
            ),
            method: Method::POST,
            headers: HeaderMap::new(),
            query_params: HashMap::new(),
            body: Some(json!({
                "id": "1",
                "Submit": "Submit"
            })),
            body_format: BodyFormat::Auto,
            fields: vec!["id".to_owned()],
            include_time_based: true,
            confirm_time_based: true,
            time_confirmation_runs: DEFAULT_TIME_CONFIRMATION_RUNS,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_time_delay_ms: DEFAULT_TIME_DELAY_MS,
        };

        let body = plan.body.as_ref().expect("body should exist");
        let payloads = payloads_for_field(&plan, "id");

        assert_eq!(
            resolve_body_format(&HeaderMap::new(), BodyFormat::Auto, body),
            BodyFormat::Form
        );
        assert!(payloads.boolean_pairs.iter().any(|pair| {
            pair.name == "numeric_and"
                && pair.true_payload == "1 AND 1=1"
                && pair.false_payload == "1 AND 1=2"
        }));
        assert!(payloads.boolean_pairs.iter().any(|pair| {
            pair.name == "quoted_and"
                && pair.true_payload == "1' AND '1'='1"
                && pair.false_payload == "1' AND '1'='2"
        }));
        assert!(
            payloads
                .time_payloads
                .iter()
                .any(|payload| payload.value == "1 AND SLEEP(2)")
        );
    }

    #[test]
    fn detects_boolean_difference_from_dvwa_style_result_markers() {
        let baseline = ProbeObservation {
            status: Some(200),
            latency_ms: 50,
            body_len: 120,
            body_preview: "<html>First name: admin<br>Surname: admin</html>".to_owned(),
            error: None,
        };
        let pair = BooleanProbeObservation {
            name: "quoted_and".to_owned(),
            true_payload: "1' AND '1'='1".to_owned(),
            false_payload: "1' AND '1'='2".to_owned(),
            true_observation: ProbeObservation {
                status: Some(200),
                latency_ms: 55,
                body_len: 120,
                body_preview: "<html>First name: admin<br>Surname: admin</html>".to_owned(),
                error: None,
            },
            false_observation: ProbeObservation {
                status: Some(200),
                latency_ms: 52,
                body_len: 118,
                body_preview: "<html>ID is MISSING from the database.</html>".to_owned(),
                error: None,
            },
        };

        let evidence =
            boolean_difference_evidence(&baseline, &pair).expect("difference should be detected");

        assert!(evidence.contains("quoted_and"));
        assert!(evidence.contains("1' AND '1'='1"));
        assert!(evidence.contains("1' AND '1'='2"));
    }

    #[test]
    fn confirmed_time_delay_upgrades_field_and_issues_to_high() {
        let baseline = ProbeObservation {
            status: Some(200),
            latency_ms: 80,
            body_len: 100,
            body_preview: "baseline".to_owned(),
            error: None,
        };
        let confirmation = TimeDelayConfirmation {
            probe_name: "numeric_sleep".to_owned(),
            payload: "1 AND SLEEP(2)".to_owned(),
            confirmed: true,
            runs: vec![
                TimeDelayConfirmationRun {
                    baseline_latency_ms: 82,
                    delayed_latency_ms: 2100,
                    delta_ms: 2018,
                },
                TimeDelayConfirmationRun {
                    baseline_latency_ms: 79,
                    delayed_latency_ms: 2080,
                    delta_ms: 2001,
                },
            ],
        };

        let finding = analyze_field(
            "id",
            &baseline,
            &[],
            &[],
            &[],
            &[confirmation],
            DEFAULT_TIME_DELAY_MS,
        );
        let issues = issues_from_findings(&[finding]);

        assert_eq!(issues[0].title, "Possible SQL injection input point");
        assert_eq!(issues[0].severity, "high");
        assert!(
            issues
                .iter()
                .any(|issue| issue.title == "Time-based SQL injection confirmed"
                    && issue.severity == "high")
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue.title == "Time-delay response signal")
        );
    }

    #[test]
    fn builds_human_readable_issues_from_database_error_signal() {
        let findings = vec![FieldFinding {
            field: "id".to_owned(),
            risk: "high".to_owned(),
            signals: vec![RiskSignal {
                kind: "database_error_leak".to_owned(),
                severity: "high".to_owned(),
                evidence: "response contained database error pattern: sql syntax".to_owned(),
            }],
        }];

        let issues = issues_from_findings(&findings);
        let summary = database_risk_summary("high", 1, issues.len(), &issues);

        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].title, "SQL/database error information disclosure");
        assert_eq!(issues[0].affected_fields, vec!["id".to_owned()]);
        assert_eq!(issues[1].title, "Possible SQL injection input point");
        assert_eq!(issues[1].severity, "high");
        assert!(summary.contains("2 issue(s)"));
        assert!(summary.contains("SQL/database error information disclosure (id)"));
        assert!(summary.contains("Possible SQL injection input point (id)"));
    }

    #[tokio::test]
    async fn registry_includes_database_risk_scan() {
        let registry = ToolRegistry::with_builtins().expect("builtins should register");

        assert!(registry.has("database_risk_scan"));
        assert!(registry.spec("database_risk_scan").is_some());
    }
}
