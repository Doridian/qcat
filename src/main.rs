use clap::Parser;
use qcat::{
    args, core,
    crypto::{CryptoMaterial, QcatCryptoConfig},
    utils::receive_password_input,
};
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::Mutex;
use webpki::types::PrivateKeyDer;

// TODO:
// - add support for reading/writing from files rather than just stdin/stdout
// - add logging
// - fix names - remove qcat from a bunch of stuff since it's repetitive if its already in this crate

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = args::Args::parse();

    env_logger::init();

    let ip_addr = IpAddr::from_str(&args.hostname)?;
    let socket_addr = SocketAddr::new(ip_addr, args.port);

    if args.listen {
        let crypto = CryptoMaterial::generate()?;
        // need to get password here
        eprintln!("Generated salt + password: \"{}\"", crypto.password());

        let private_key_der = PrivateKeyDer::Pkcs8(crypto.private_key().clone_key());
        let config = QcatCryptoConfig::new(crypto.certificate(), &private_key_der);
        let mut server = core::QcatServer::new(socket_addr, config)?;

        // we spawn a new tokio task for each connection, so wrap stdout in arc + mutex
        let stdout = Mutex::new(tokio::io::stdout());
        let mut stdout_arc = Arc::new(stdout);

        server.run(&mut stdout_arc).await?;
    } else {
        let mut stdin = tokio::io::stdin();

        let password = receive_password_input().await?;
        let crypto = CryptoMaterial::generate_from_password(password)?;

        let private_key_der = PrivateKeyDer::Pkcs8(crypto.private_key().clone_key());
        let config = QcatCryptoConfig::new(crypto.certificate(), &private_key_der);
        let mut client = core::QcatClient::new(config)?;

        client.run(socket_addr, &mut stdin).await?;
    }

    Ok(())
}
