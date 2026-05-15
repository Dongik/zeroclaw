//! AgentOS desktop integration endpoints.
//!
//! These handlers expose the existing OAuth helpers as a small local API so a
//! desktop shell can drive login without parsing CLI output.

use super::{AppState, api::require_auth};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use zeroclaw_providers::auth::{AuthService, openai_oauth};

const OPENAI_CODEX_PROVIDER: &str = "openai-codex";
const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Deserialize)]
pub struct AgentosOauthQuery {
    pub profile: Option<String>,
    pub login_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum LoginStatus {
    Pending,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize)]
struct LoginState {
    login_id: String,
    provider: String,
    profile: String,
    status: LoginStatus,
    authorize_url: String,
    message: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct AuthProfileStatus {
    authenticated: bool,
    provider: String,
    profile: String,
    account_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct StartOauthResponse {
    ok: bool,
    login_id: String,
    provider: String,
    profile: String,
    authorize_url: String,
    callback_url: &'static str,
    status: LoginStatus,
}

#[derive(Debug, Serialize)]
struct OauthStatusResponse {
    ok: bool,
    login: Option<LoginState>,
    auth: AuthProfileStatus,
}

fn login_store() -> &'static Mutex<HashMap<String, LoginState>> {
    static STORE: OnceLock<Mutex<HashMap<String, LoginState>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn update_login(login_id: &str, status: LoginStatus, message: Option<String>) {
    let Ok(mut guard) = login_store().lock() else {
        return;
    };
    if let Some(login) = guard.get_mut(login_id) {
        login.status = status;
        login.message = message;
        login.completed_at = Some(Utc::now());
    }
}

async fn profile_status(
    config: &zeroclaw_config::schema::Config,
    profile: &str,
) -> AuthProfileStatus {
    let auth_service = AuthService::from_config(config);
    match auth_service
        .get_profile(OPENAI_CODEX_PROVIDER, Some(profile))
        .await
    {
        Ok(Some(auth_profile)) => AuthProfileStatus {
            authenticated: auth_profile.token_set.is_some() || auth_profile.token.is_some(),
            provider: OPENAI_CODEX_PROVIDER.to_string(),
            profile: profile.to_string(),
            account_id: auth_profile.account_id,
            expires_at: auth_profile.token_set.and_then(|tokens| tokens.expires_at),
        },
        _ => AuthProfileStatus {
            authenticated: false,
            provider: OPENAI_CODEX_PROVIDER.to_string(),
            profile: profile.to_string(),
            account_id: None,
            expires_at: None,
        },
    }
}

pub async fn handle_openai_codex_oauth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentosOauthQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let profile = query.profile.unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let login_id = uuid::Uuid::new_v4().to_string();
    let pkce = openai_oauth::generate_pkce_state();
    let authorize_url = openai_oauth::build_authorize_url(&pkce);
    let started_at = Utc::now();
    let login = LoginState {
        login_id: login_id.clone(),
        provider: OPENAI_CODEX_PROVIDER.to_string(),
        profile: profile.clone(),
        status: LoginStatus::Pending,
        authorize_url: authorize_url.clone(),
        message: None,
        started_at,
        completed_at: None,
    };

    if let Ok(mut guard) = login_store().lock() {
        guard.insert(login_id.clone(), login);
    }

    let config = state.config.lock().clone();
    let login_id_for_task = login_id.clone();
    let profile_for_task = profile.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let code = match openai_oauth::receive_loopback_code(&pkce.state, Duration::from_secs(180))
            .await
        {
            Ok(code) => code,
            Err(err) => {
                update_login(
                    &login_id_for_task,
                    LoginStatus::Error,
                    Some(err.to_string()),
                );
                return;
            }
        };

        let token_set = match openai_oauth::exchange_code_for_tokens(&client, &code, &pkce).await {
            Ok(token_set) => token_set,
            Err(err) => {
                update_login(
                    &login_id_for_task,
                    LoginStatus::Error,
                    Some(err.to_string()),
                );
                return;
            }
        };

        let account_id = openai_oauth::extract_account_id_from_jwt(&token_set.access_token);
        let auth_service = AuthService::from_config(&config);
        match auth_service
            .store_openai_tokens(&profile_for_task, token_set, account_id, true)
            .await
        {
            Ok(_) => update_login(
                &login_id_for_task,
                LoginStatus::Complete,
                Some("OpenAI Codex authentication completed".to_string()),
            ),
            Err(err) => update_login(
                &login_id_for_task,
                LoginStatus::Error,
                Some(err.to_string()),
            ),
        }
    });

    Json(StartOauthResponse {
        ok: true,
        login_id,
        provider: OPENAI_CODEX_PROVIDER.to_string(),
        profile,
        authorize_url,
        callback_url: openai_oauth::OPENAI_OAUTH_REDIRECT_URI,
        status: LoginStatus::Pending,
    })
    .into_response()
}

pub async fn handle_openai_codex_oauth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentosOauthQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let profile = query.profile.unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let login = query.login_id.and_then(|login_id| {
        login_store()
            .lock()
            .ok()
            .and_then(|guard| guard.get(&login_id).cloned())
    });
    let config = state.config.lock().clone();
    let auth = profile_status(&config, &profile).await;

    (
        StatusCode::OK,
        Json(OauthStatusResponse {
            ok: true,
            login,
            auth,
        }),
    )
        .into_response()
}
