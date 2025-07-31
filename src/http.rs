use crate::connection::{ConnKey, Connection};
use axum::Router;
use axum::response::Html;
use axum::routing::get;
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;

const INDEX_PAGE: &str = include_str!("../static/index.html");
const CONNECTIONS_PAGE: &str = include_str!("../static/connections.html");

pub trait ConnTrack {
    fn get_active_conn(&self) -> HashMap<ConnKey, Connection>;
}

pub struct Server {
    port: u16,
    router: Router,
}

impl Server {
    pub fn new<CT: ConnTrack + Send + Sync + 'static>(port: u16, conn_track: Arc<CT>) -> Server {
        Server {
            port,
            router: Server::router(conn_track),
        }
    }

    fn router<CT: ConnTrack + Send + Sync + 'static>(conn_track: Arc<CT>) -> Router {
        Router::new()
            .route("/", get(async move || Html(INDEX_PAGE)))
            .route(
                "/active",
                get({
                    let conn_track = conn_track.clone();
                    async move || {
                        let active_conn = conn_track.get_active_conn();

                        Html(
                            CONNECTIONS_PAGE
                                .replace("{{connection_count}}", &active_conn.len().to_string())
                                .replace(
                                    "{{connection_rows}}",
                                    &active_conn
                                        .iter()
                                        .map(|(k, v)| {
                                            format!(
                                                "<tr><td>{k}</td><td>{}</td></tr>",
                                                serde_json::to_string(v).unwrap()
                                            )
                                        })
                                        .collect::<Vec<String>>()
                                        .join("\n"),
                                ),
                        )
                    }
                }),
            )
    }

    pub async fn run(self) {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        info!("Listening on {addr}");

        axum::serve(listener, self.router)
            .await
            .unwrap_or_else(|e| {
                error!("server error: {e}");
                std::process::exit(1);
            })
    }
}
