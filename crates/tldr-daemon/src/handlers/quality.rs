//! Quality handlers: smells, maintainability
//!
//! These handlers provide code quality analysis including code smell detection
//! and maintainability index calculation.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Deserialize;

use crate::server::{DaemonResponse, HandlerError};
use crate::state::DaemonState;

use tldr_core::{
    detect_smells_with_walker_opts, maintainability_index, validate_file_path, Language,
    MaintainabilityReport, SmellType, SmellsReport, SmellsWalkerOpts, ThresholdPreset,
};

// =============================================================================
// Smells Handler
// =============================================================================

/// Smells request parameters
#[derive(Debug, Deserialize)]
pub struct SmellsRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub threshold: Option<String>,
    #[serde(default)]
    pub smell_type: Option<String>,
    #[serde(default)]
    pub suggest: bool,
    /// v0.2.3 (#1.D): caller-supplied file list (empty = walk).
    #[serde(default)]
    pub files: Option<Vec<PathBuf>>,
    /// v0.2.3 (#1.D): include test-pattern findings.
    #[serde(default)]
    pub include_tests: Option<bool>,
}

/// Smells handler - detects code smells
pub async fn smells(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<SmellsRequest>,
) -> Result<Json<DaemonResponse<SmellsReport>>, HandlerError> {
    state.touch();

    let project = state.project().clone();
    // VAL-006 / issue #5 (broader audit): when the caller supplies an explicit
    // path, validate it stays inside the project root before any filesystem
    // walk. When no path is given, default to scanning the project root
    // (already trusted). Mirrors the M1 fix in `handlers/security.rs::secrets`.
    let path = if let Some(p) = &request.path {
        validate_file_path(p, Some(&project))
            .map_err(|e| HandlerError(axum::http::StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        project
    };

    // Parse threshold preset
    let threshold = match request.threshold.as_deref() {
        Some("strict") => ThresholdPreset::Strict,
        Some("relaxed") => ThresholdPreset::Relaxed,
        _ => ThresholdPreset::Default,
    };

    // Parse smell type filter
    let smell_type: Option<SmellType> =
        request
            .smell_type
            .as_deref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "godclass" | "god_class" => Some(SmellType::GodClass),
                "longmethod" | "long_method" => Some(SmellType::LongMethod),
                "featureenvy" | "feature_envy" => Some(SmellType::FeatureEnvy),
                "dataclumps" | "data_clumps" => Some(SmellType::DataClumps),
                "longparameterlist" | "long_parameter_list" => Some(SmellType::LongParameterList),
                _ => None,
            });

    let suggest = request.suggest;

    // v0.2.3 (#1.D): build walker opts so the daemon honors --files and
    // --include-tests just like the CLI direct-compute path. Default
    // include_tests=false matches the new CLI default; the CLI sets it true
    // when --files is non-empty before sending, but we OR in `files.is_some()`
    // here as a safety net.
    let request_files = request.files.unwrap_or_default();
    let include_tests = request.include_tests.unwrap_or(false) || !request_files.is_empty();
    let walker_opts = SmellsWalkerOpts {
        no_default_ignore: false,
        lang: None,
        files: request_files,
        include_tests,
    };

    // Run in blocking context (M10)
    let result = tokio::task::spawn_blocking(move || {
        detect_smells_with_walker_opts(&path, threshold, smell_type, suggest, walker_opts)
    })
    .await
    .map_err(|e| {
        HandlerError(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Task join error: {}", e),
        )
    })?
    .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DaemonResponse::ok(result)))
}

// =============================================================================
// Maintainability Handler
// =============================================================================

/// Maintainability request parameters
#[derive(Debug, Deserialize)]
pub struct MaintainabilityRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub include_halstead: bool,
    #[serde(default)]
    pub language: Option<String>,
}

/// Maintainability handler - calculates maintainability index
pub async fn maintainability(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<MaintainabilityRequest>,
) -> Result<Json<DaemonResponse<MaintainabilityReport>>, HandlerError> {
    state.touch();

    let project = state.project().clone();
    // VAL-006 / issue #5 (broader audit): when the caller supplies an explicit
    // path, validate it stays inside the project root before any filesystem
    // walk. When no path is given, default to scanning the project root
    // (already trusted). Mirrors the M1 fix in `handlers/security.rs::secrets`.
    let path = if let Some(p) = &request.path {
        validate_file_path(p, Some(&project))
            .map_err(|e| HandlerError(axum::http::StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        project
    };

    let include_halstead = request.include_halstead;

    // Parse optional language
    let language: Option<Language> = request.language.as_deref().and_then(|s| s.parse().ok());

    // Run in blocking context (M10)
    let result = tokio::task::spawn_blocking(move || {
        maintainability_index(&path, include_halstead, language)
    })
    .await
    .map_err(|e| {
        HandlerError(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Task join error: {}", e),
        )
    })?
    .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DaemonResponse::ok(result)))
}
