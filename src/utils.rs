use crate::crypto::SaltedPassphrase;
use std::{self, str::FromStr};

/// Receive a passphrase input by the user. Intended for use by the client with the generated server passphrase
pub fn receive_passphrase_input() -> Result<SaltedPassphrase, Box<dyn std::error::Error>> {
    let received_passphrase = rpassword::prompt_password("Enter password from server: ")?;
    Ok(SaltedPassphrase::from_str(received_passphrase.trim())?)
}
