mod proto {
    tonic::include_proto!("meesign");
}

use clap::Parser;
use proto::mpc_client::MpcClient;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Request;

lazy_static::lazy_static! {
    static ref DATA_DIR: std::path::PathBuf = std::path::PathBuf::from_iter(&[std::env!("CARGO_MANIFEST_DIR"), "data"]);
    static ref CA_CERT: Certificate = {
        let ca_cert = std::fs::read_to_string(DATA_DIR.join("meesign-ca-cert.pem")).unwrap();
        Certificate::from_pem(ca_cert.as_bytes())
    };
}

async fn get_server_version(addr: (&str, u16)) -> Result<String, Box<dyn std::error::Error>> {
    let tls = ClientTlsConfig::new()
        .domain_name(addr.0)
        .ca_certificate(CA_CERT.clone());

    let channel = Channel::from_shared(format!("https://{}:{}", addr.0, addr.1))?
        .tls_config(tls.clone())?
        .connect()
        .await?;

    let mut client = MpcClient::new(channel);

    let request = Request::new(proto::ServerInfoRequest {});

    let response = client.get_server_info(request).await?.into_inner();
    Ok(response.version)
}

async fn try_load_credentials() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let id = tokio::fs::read(DATA_DIR.join("client_id.bin")).await?;
    let cert = tokio::fs::read(DATA_DIR.join("client_cert.pem")).await?;
    let key = tokio::fs::read(DATA_DIR.join("client_key.pem")).await?;
    Ok((id, cert, key))
}

async fn register(
    addr: (&str, u16),
    name: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(CA_CERT.clone());

    let channel = Channel::from_shared(format!("https://{}:{}", addr.0, addr.1))?
        .tls_config(tls.clone())?
        .connect()
        .await?;

    let mut client = MpcClient::new(channel);

    let (key, csr) = meesign_crypto::auth::gen_key_with_csr(name)?;

    let response = client
        .register(proto::RegistrationRequest {
            name: name.to_string(),
            csr,
        })
        .await?
        .into_inner();

    let id = response.device_id;
    let cert = meesign_crypto::auth::cert_der_to_pem(&response.certificate);
    let key = meesign_crypto::auth::key_der_to_pem(&key);

    std::fs::write(DATA_DIR.join("client_key.pem"), &key)?;
    std::fs::write(DATA_DIR.join("client_cert.pem"), &cert)?;
    std::fs::write(DATA_DIR.join("client_id.bin"), &id)?;

    Ok((id, cert, key))
}

async fn establish_channel(
    addr: (&str, u16),
    cert: Vec<u8>,
    key: Vec<u8>,
) -> Result<Channel, Box<dyn std::error::Error>> {
    let tls = ClientTlsConfig::new()
        .domain_name(addr.0)
        .ca_certificate(CA_CERT.clone())
        .identity(Identity::from_pem(cert, key));

    let channel = Channel::from_shared(format!("https://{}:{}", addr.0, addr.1))?
        .tls_config(tls.clone())?
        .connect()
        .await?;

    Ok(channel)
}

#[derive(Parser, Debug)]
/// MeeSign CLI client
#[command(version)]
struct Args {
    /// Server address
    #[arg(short, long, default_value_t = String::from("meesign.crocs.fi.muni.cz"))]
    server: String,
    /// Server port
    #[arg(short, long, default_value_t = 1337)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr = (args.server.as_str(), args.port);

    println!(
        "Connecting to server version {}",
        get_server_version(addr).await?
    );

    let (id, cert, key) = if let Ok(credentials) = try_load_credentials().await {
        credentials
    } else {
        println!("No client credentials found, registering...");
        register(addr, "RustClient").await?
    };

    println!("Obtained ID {}", hex::encode(&id));

    let mut client = MpcClient::new(establish_channel(addr, cert, key).await?);

    let request = Request::new(proto::TasksRequest {
        device_id: Some(id),
    });

    let response = client.get_tasks(request).await?.into_inner();

    for task in response.tasks {
        println!("Task: {:?}", task);
    }

    Ok(())
}
