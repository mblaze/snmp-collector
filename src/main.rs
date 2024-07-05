mod snmp;
mod http_api;

#[tokio::main]
async fn main() {
  http_api::serve().await;
}
