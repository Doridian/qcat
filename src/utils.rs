use std::error::Error;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::crypto::QcatPassword;

/// Receive a password input by the user. Intended for use by the client with the generated server password
pub async fn receive_password_input<T: AsyncReadExt + Unpin>(
    input: &mut T,
) -> Result<QcatPassword, Box<dyn Error>> {
    eprintln!("enter password:");
    let mut reader = BufReader::new(input);
    let mut received_password = String::new();

    reader.read_line(&mut received_password).await?;
    // TODO: clean up this ownership?
    let received_password = received_password.trim();

    Ok(QcatPassword::new(received_password.to_owned()))
}
