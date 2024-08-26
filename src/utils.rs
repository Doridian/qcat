use crate::crypto::SaltedPassword;
use std::{self, str::FromStr};

/// Receive a password input by the user. Intended for use by the client with the generated server password
pub async fn receive_password_input() -> Result<SaltedPassword, Box<dyn std::error::Error>> {
    let received_password = rpassword::prompt_password("Enter password from server: ")?;
    Ok(SaltedPassword::from_str(received_password.trim())?)
}
