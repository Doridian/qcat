use clap::Parser;
use log::info;
use qcat::{
    args, core,
    crypto::{CryptoMaterial, QcatCryptoConfig},
};
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use std::env;
use tokio::sync::Mutex;
use webpki::types::PrivateKeyDer;
use std::{self, str::FromStr};
use qcat::crypto::SaltedPassphrase;

// TODO:
// - add support for reading/writing from files rather than just stdin/stdout
// - fix args to be more like nc
// - ipv6 support, try to resolve addresses rather than just using ip addrs from args (i.e. should be able to type "localhost")
// - remove RSA support
// - look at cert params and defaults

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = args::Args::parse();

    let log_level_filter = if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level_filter)
        .init();

    let ip_addr = IpAddr::from_str(&args.hostname)?;
    let socket_addr = SocketAddr::new(ip_addr, args.port);


    let passphrase = SaltedPassphrase::from_str(env::var("QUICPASS")?.as_str())?;
    let crypto = CryptoMaterial::generate_from_passphrase(passphrase)?;
    info!("Generated salt + passphrase: \"{}\"", crypto.passphrase());

    if args.listen {
        let private_key_der = PrivateKeyDer::Pkcs8(crypto.private_key().clone_key());
        let config = QcatCryptoConfig::new(crypto.certificate(), &private_key_der);
        let mut server = core::QcatServer::new(socket_addr, config)?;

        // we spawn a new tokio task for each connection, so wrap stdout in arc + mutex
        let stdout = Mutex::new(tokio::io::stdout());
        let mut stdout_arc = Arc::new(stdout);

        server.run(&mut stdout_arc).await?;
    } else {
        let mut stdin = tokio::io::stdin();

        let private_key_der = PrivateKeyDer::Pkcs8(crypto.private_key().clone_key());
        let config = QcatCryptoConfig::new(crypto.certificate(), &private_key_der);
        let mut client = core::QcatClient::new(config)?;

        client.run(socket_addr, &mut stdin).await?;
    }

    Ok(())
}
