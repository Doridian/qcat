use std::{self, str::FromStr};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::crypto::SaltedPassword;

/// Receive a password input by the user. Intended for use by the client with the generated server password
pub async fn receive_password_input<T: AsyncReadExt + Unpin>(
    input: &mut T,
) -> Result<SaltedPassword, Box<dyn std::error::Error>> {
    eprintln!("Enter password from server:");
    let mut reader = BufReader::new(input);
    let mut received_password = String::new();

    reader.read_line(&mut received_password).await?;
    let received_password = received_password.trim();

    Ok(SaltedPassword::from_str(received_password)?)
}
