// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use axum::extract::State;
use axum::response::{IntoResponse, Json};
use axum::{http::StatusCode, routing::put, Router};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use env_logger::Env;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::runtime::events::{Event as K8sEvent, EventType, Recorder, Reporter};
use kube::{Api, Client, Resource};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use trusted_cluster_operator_lib::endpoints::ATTESTATION_KEY_REGISTER_RESOURCE;
use trusted_cluster_operator_lib::{
    generate_owner_reference, get_trusted_execution_cluster, AttestationKey, AttestationKeySpec,
};

#[derive(Parser)]
#[command(name = "attestation-key-register")]
#[command(about = "HTTP server that accepts attestation key registrations")]
struct Args {
    #[arg(short, long, default_value = "8001")]
    port: u16,
    #[arg(long)]
    cert_path: Option<String>,
    #[arg(long)]
    key_path: Option<String>,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    recorder: Recorder,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationKeyRegistration {
    /// Public attestation key
    #[serde(alias = "attestation_key")]
    public_key: String,

    /// Optional uuid used for the machine registration
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
}

async fn handle_registration(
    State(state): State<AppState>,
    Json(registration): Json<AttestationKeyRegistration>,
) -> impl IntoResponse {
    info!("Received registration request: {registration:?}");
    let client = state.client;
    let recorder = state.recorder;

    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e:?}");
        let msg = serde_json::json!({
            "status": "error",
            "message": format!("{e:#}"),
        });
        (code, Json(msg))
    };

    let api: Api<AttestationKey> = Api::default_namespaced(client.clone());

    // Get the TrustedExecutionCluster to use as owner reference
    let cluster = match get_trusted_execution_cluster(client.clone()).await {
        Ok(c) => c,
        Err(e) => return internal_error(e.context("Failed to get TrustedExecutionCluster")),
    };

    let owner_reference = match generate_owner_reference(&cluster) {
        Ok(o) => o,
        Err(e) => return internal_error(e.context("Failed to generate owner reference")),
    };

    match api.list(&Default::default()).await {
        Ok(existing_keys) => {
            for key in existing_keys.items {
                if key.spec.public_key == registration.public_key {
                    let key_ref: ObjectReference = key.object_ref(&());
                    let existing_name = key.metadata.name.unwrap_or_default();
                    error!(
                        "Duplicate public key detected: already exists in AttestationKey '{existing_name}'"
                    );
                    if let Err(e) = recorder
                        .publish(
                            &K8sEvent {
                                type_: EventType::Warning,
                                reason: "DuplicateKeyRejected".into(),
                                note: Some(format!(
                                    "Duplicate registration attempt for AttestationKey '{existing_name}'"
                                )),
                                action: "Registering".into(),
                                secondary: None,
                            },
                            &key_ref,
                        )
                        .await
                    {
                        warn!("Failed to publish event: {e}");
                    }
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "status": "error",
                            "message": "Public key already registered",
                        })),
                    );
                }
            }
        }
        Err(e) => {
            return internal_error(
                anyhow::Error::from(e).context("Failed to check for existing keys"),
            )
        }
    }

    let name = format!("ak-{}", Uuid::new_v4());
    let attestation_key = AttestationKey {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: AttestationKeySpec {
            public_key: registration.public_key,
            uuid: registration.uuid,
        },
        status: None,
    };

    match api.create(&Default::default(), &attestation_key).await {
        Ok(created) => {
            let created_ref: ObjectReference = created.object_ref(&());
            let name = created.metadata.name.unwrap_or_default();
            info!("Successfully created AttestationKey: {name}",);
            if let Err(e) = recorder
                .publish(
                    &K8sEvent {
                        type_: EventType::Normal,
                        reason: "AttestationKeyRegistered".into(),
                        note: Some(format!("AttestationKey '{name}' registered")),
                        action: "Registering".into(),
                        secondary: None,
                    },
                    &created_ref,
                )
                .await
            {
                warn!("Failed to publish event: {e}");
            }
            let json = Json(serde_json::json!({
                "status": "success",
            }));
            (StatusCode::CREATED, json)
        }
        Err(e) => internal_error(anyhow::Error::from(e).context("Failed to create AttestationKey")),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let endpoint = format!("/{ATTESTATION_KEY_REGISTER_RESOURCE}");
    let err = "failed to create Kubernetes client";
    let client = Client::try_default().await.expect(err);
    let reporter = Reporter {
        controller: "attestation-key-register".into(),
        instance: std::env::var("CONTROLLER_POD_NAME").ok(),
    };
    let state = AppState {
        recorder: Recorder::new(client.clone(), reporter),
        client,
    };
    let app = Router::new()
        .route(&endpoint, put(handle_registration))
        .with_state(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let service = app.into_make_service();

    let run = if let (Some(cert_path), Some(key_path)) = (args.cert_path, args.key_path) {
        let config = OpenSSLConfig::from_pem_file(cert_path, key_path).expect("invalid PEM files");
        info!("Starting attestation key registration server on https://{addr}");
        axum_server::bind_openssl(addr, config).serve(service).await
    } else {
        info!("Starting attestation key registration server on http://{addr}");
        axum_server::bind(addr).serve(service).await
    };
    run.expect("Server failed");
}
