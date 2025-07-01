use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, extract::Query, response::Html, routing::get};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, time::timeout};

use crate::{Error, Result};

const SSO_URL_ENDPOINT: &str = "/session/authenticator-request";
const BROWSER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Serialize)]
struct AuthRequest {
    data: AuthData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
struct AuthData {
    account_name: String,
    login_name: String,
    authenticator: String,
    browser_mode_redirect_port: u16,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    data: AuthResponseData,
    success: bool,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseData {
    sso_url: String,
    proof_key: String,
}

#[derive(Deserialize)]
struct TokenCallback {
    #[serde(alias = "token", alias = "code")]
    token: Option<String>,
}

pub async fn authenticate_via_browser(
    http: &Client,
    account: &str,
    username: &str,
) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (sso_url, proof_key) = get_sso_url(http, account, username, port).await?;

    let token_state = Arc::new(Mutex::new(None::<String>));
    let token = Arc::clone(&token_state);

    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<TokenCallback>| {
            let state = token.clone();
            async move {
                params.token.map_or_else(
                    || Html("Error: No token received"),
                    |token| {
                        *state.lock().unwrap() = Some(token);
                        Html("Authentication successful. You can close this window now.")
                    },
                )
            }
        }),
    );

    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    webbrowser::open(&sso_url)
        .map_err(|e| Error::Communication(format!("Failed to open browser: {e}")))?;

    let result = timeout(BROWSER_TIMEOUT, async {
        loop {
            if let Some(token) = &*token_state.lock().unwrap() {
                return Ok(token.clone());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    server.abort();

    match result {
        Ok(Ok(token)) => validate_saml_response(http, account, username, &token, &proof_key).await,
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Communication("Browser authentication timeout".into())),
    }
}

async fn get_sso_url(
    http: &Client,
    account: &str,
    username: &str,
    port: u16,
) -> Result<(String, String)> {
    let url = format!("https://{account}.snowflakecomputing.com{SSO_URL_ENDPOINT}");

    let response = http
        .post(&url)
        .json(&AuthRequest {
            data: AuthData {
                account_name: account.into(),
                login_name: username.into(),
                authenticator: "EXTERNALBROWSER".into(),
                browser_mode_redirect_port: port,
            },
        })
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        return Err(Error::Communication(format!("Failed to get SSO URL: {body}")));
    }

    let resp: AuthResponse = serde_json::from_str(&body)
        .map_err(|_| Error::Communication(format!("Invalid response: {body}")))?;

    if !resp.success {
        return Err(Error::Communication(resp.message.unwrap_or_else(|| "Unknown error".into())));
    }

    Ok((resp.data.sso_url, resp.data.proof_key))
}

async fn validate_saml_response(
    http: &Client,
    account: &str,
    username: &str,
    saml_response: &str,
    proof_key: &str,
) -> Result<String> {
    let url = format!("https://{account}.snowflakecomputing.com/session/v1/login-request");
    let login_data = serde_json::json!({
        "data": {
            "LOGIN_NAME": username,
            "ACCOUNT_NAME": account,
            "AUTHENTICATOR": "EXTERNALBROWSER",
            "TOKEN": saml_response,
            "PROOF_KEY": proof_key,
        }
    });

    let response = http.post(&url).json(&login_data).send().await?;
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        return Err(Error::Communication(format!("Failed to validate SAML response: {body}")));
    }

    let resp: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| Error::Communication(format!("Invalid response: {body}")))?;

    match (resp["success"].as_bool(), resp["data"]["token"].as_str()) {
        (Some(true), Some(token)) => Ok(token.into()),
        (Some(true), None) => Err(Error::Communication("No session token in response".into())),
        _ => Err(Error::Communication(resp["message"].as_str().unwrap_or("Unknown error").into())),
    }
}
