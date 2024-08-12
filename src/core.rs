use s2n_quic::{client::Connect, Client, Server};
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::crypto::QcatCryptoConfig;

/// Server component of qcat
pub struct QcatServer {
    server: Server,
}

impl QcatServer {
    pub fn new(socket_addr: SocketAddr, config: QcatCryptoConfig) -> Result<Self, Box<dyn Error>> {
        let tls_config = config.build_server_config()?;
        // TODO: see if we can configure the server with the builder rather than new
        let rustls_server = s2n_quic_rustls::Server::new(tls_config);
        let server = Server::builder()
            .with_tls(rustls_server)?
            .with_io(socket_addr)?
            .start()?;

        Ok(Self { server })
    }

    /// Starts the server
    pub async fn run<T: AsyncWriteExt + Unpin + Send + 'static>(
        &mut self,
        output: &mut Arc<Mutex<T>>,
    ) -> Result<(), Box<dyn Error>> {
        while let Some(mut conn) = self.server.accept().await {
            let output_clone = Arc::clone(output);
            tokio::spawn(async move {
                while let Ok(Some(mut stream)) = conn.accept_receive_stream().await {
                    while let Ok(Some(data)) = stream.receive().await {
                        let mut output_ref = output_clone.lock().await;
                        output_ref.write_all(&data).await.unwrap();
                    }
                }
            });
        }

        Ok(())
    }
}

/// Client component of qcat
pub struct QcatClient {
    client: Client,
}

impl QcatClient {
    pub fn new(config: QcatCryptoConfig) -> Result<Self, Box<dyn Error>> {
        // TODO: ipv6, cleanup
        let tls_config = config.build_client_config()?;
        // TODO: see if we can configure the client with the builder rather than new
        let rustls_client = s2n_quic_rustls::Client::new(tls_config);
        let client = Client::builder()
            .with_tls(rustls_client)?
            .with_io("0.0.0.0:0")? // TODO: configure this
            .start()?;

        Ok(Self { client })
    }

    /// Starts the client
    pub async fn run<T: AsyncReadExt + Unpin + ?Sized>(
        &mut self,
        addr: SocketAddr,
        input: &mut T,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: servername?
        let connect = Connect::new(addr).with_server_name("localhost");
        let mut conn = self.client.connect(connect).await?;

        conn.keep_alive(true)?;

        let mut stream = conn.open_send_stream().await?;

        tokio::io::copy(input, &mut stream).await?;
        stream.close().await?;

        Ok(())
    }
}
