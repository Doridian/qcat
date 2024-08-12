use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use pbkdf2::pbkdf2_hmac_array;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use s2n_quic::provider::tls::rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    PeerIncompatible, PeerMisbehaved, ServerConfig, SignatureScheme,
};
use s2n_quic_rustls::rustls::{crypto::aws_lc_rs, version::TLS13, SupportedProtocolVersion};
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use webpki::{
    types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
        SignatureVerificationAlgorithm, UnixTime,
    },
    EndEntityCert,
};

const QCAT_ALPN: &[u8; 4] = b"qcat";
static SUPPORTED_TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13];

/// Our custom ALPN protocol. Not really a protocol per se as the client is just sending raw bytes
#[derive(Debug)]
struct QcatAlpnProtocol(Vec<Vec<u8>>);

impl QcatAlpnProtocol {
    pub fn new() -> Self {
        Self(vec![QCAT_ALPN.to_vec()])
    }
}

/// Newtype for a password String we generate
#[derive(Debug)]
pub struct QcatPassword(String);

impl QcatPassword {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Our cert verifier. This can verify both client and server certs, it simply checks if the certs are the same and
/// verifies the other party holds the certificate's private key material
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned_cert: CertificateDer<'static>,
    supported_algs: WebPkiSupportedAlgorithms,
    /// We need to return a &[DistinguishedName] in our ClientVerifier for root_hint_subjects. We don't care about
    /// the root hints so just leave it as an empty array
    root_hints: [DistinguishedName; 0],
}

impl PinnedCertVerifier {
    fn new(pinned_cert: CertificateDer<'_>, supported_algs: WebPkiSupportedAlgorithms) -> Self {
        let pinned_cert = pinned_cert.into_owned();
        Self {
            pinned_cert,
            supported_algs,
            root_hints: [],
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if pinned_cert_is_valid(&self.pinned_cert, end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::InvalidPurpose,
            ))
        }
    }

    /// Since we are using quic only, we don't support tls1.2
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

impl ClientCertVerifier for PinnedCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // TODO: cleanup
        if pinned_cert_is_valid(&self.pinned_cert, end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::InvalidPurpose,
            ))
        }
    }

    /// Since we are using quic only, we don't support tls1.2
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Verifies a given signature scheme is supported
fn signature_scheme_is_supported(scheme: &SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
            | SignatureScheme::ED25519
            | SignatureScheme::ED448
            // TODO: clean up rsa
            | SignatureScheme::RSA_PSS_SHA512
    )
}

/// Matches a SignatureScheme to a SignatureVerificationAlgorithm
fn convert_scheme(
    supported_algs: WebPkiSupportedAlgorithms,
    scheme: &SignatureScheme,
) -> Result<&[&'static dyn SignatureVerificationAlgorithm], RustlsError> {
    supported_algs
        .mapping
        .iter()
        .filter_map(|algos| {
            if algos.0 == *scheme {
                Some(algos.1)
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
}

/// Verifies two certificates are the same. Uses best-effort constant time comparison from subtle
fn pinned_cert_is_valid(
    expected_pinned_cert: &CertificateDer<'_>,
    end_entity_cert: &CertificateDer<'_>,
) -> bool {
    // TODO: add more info here, like cert fingerprint
    expected_pinned_cert.ct_eq(end_entity_cert).into()
}

/// Verifies a tls13 signature
fn verify_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_algs: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, RustlsError> {
    if !signature_scheme_is_supported(&dss.scheme) {
        Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    } else {
        let alg = convert_scheme(*supported_algs, &dss.scheme)?[0];
        // TODO: clean up errors
        let cert = EndEntityCert::try_from(cert)
            .map_err(|_| RustlsError::General("Failed to parse cert".to_owned()))?;

        cert.verify_signature(alg, message, dss.signature())
            .map_err(|_| RustlsError::General("Failed to verify signature".to_owned()))
            .map(|_| HandshakeSignatureValid::assertion())
    }
}

/// Crypto configuration for Qcat client/server
#[derive(Debug)]
pub struct QcatCryptoConfig<'a> {
    provider: Arc<CryptoProvider>,
    pinned_cert: &'a CertificateDer<'a>,
    pinned_cert_private_key: &'a PrivateKeyDer<'a>,
    alpn_protocol: QcatAlpnProtocol,
}

impl<'a> QcatCryptoConfig<'a> {
    pub fn new(
        pinned_cert: &'a CertificateDer,
        pinned_cert_private_key: &'a PrivateKeyDer,
    ) -> Self {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let alpn_protocol = QcatAlpnProtocol::new();
        Self {
            provider,
            pinned_cert,
            pinned_cert_private_key,
            alpn_protocol,
        }
    }

    /// Build our rustls client config. This is what specifies our TLS configuration/certificate verification
    pub fn build_client_config(&self) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut client_config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(SUPPORTED_TLS_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(self.build_verifier()))
            .with_client_auth_cert(
                vec![self.pinned_cert.clone().into_owned()],
                self.pinned_cert_private_key.clone_key(),
            )?;

        client_config
            .alpn_protocols
            .clone_from(&self.alpn_protocol.0);

        Ok(client_config)
    }

    /// Build our rustls server config. This is what specifies our TLS configuration/certificate verification
    pub fn build_server_config(&self) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let mut server_config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(SUPPORTED_TLS_VERSIONS)?
            .with_client_cert_verifier(Arc::new(self.build_verifier()))
            .with_single_cert(
                vec![self.pinned_cert.clone().into_owned()],
                self.pinned_cert_private_key.clone_key(),
            )?;

        server_config
            .alpn_protocols
            .clone_from(&self.alpn_protocol.0);

        Ok(server_config)
    }

    /// Our certificate verifier, used by both client and server
    fn build_verifier(&self) -> PinnedCertVerifier {
        PinnedCertVerifier::new(
            self.pinned_cert.clone().into_owned(),
            self.provider.signature_verification_algorithms,
        )
    }
}

/// Creates and stores our crypto materials (password, private key, cert)
#[derive(Debug)]
pub struct CryptoMaterial {
    password: QcatPassword,
    private_key: PrivatePkcs8KeyDer<'static>,
    certificate: CertificateDer<'static>,
}

impl CryptoMaterial {
    pub fn private_key(&self) -> &PrivatePkcs8KeyDer<'static> {
        &self.private_key
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    pub fn password(&self) -> &QcatPassword {
        &self.password
    }

    /// Generate a cert and private key from a password. Intended to be used by the client with a password generated by the server
    pub fn generate_from_password(
        password: &str, // not using QcatPassword here since we are just accepting a string from the client - we'll
                        // wrap it in this method
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let password = QcatPassword(password.to_owned());
        let private_key = CryptoMaterial::derive_private_key(&password)?.clone_key();
        let certificate = CryptoMaterial::generate_certificate(&private_key)?.into_owned();

        Ok(Self {
            password,
            private_key,
            certificate,
        })
    }

    /// Generates all crypto material by itself. Intended to be used the the server component
    pub fn generate() -> Result<CryptoMaterial, Box<dyn std::error::Error>> {
        let password = CryptoMaterial::generate_password();
        let private_key = CryptoMaterial::derive_private_key(&password)?.clone_key();
        let certificate = CryptoMaterial::generate_certificate(&private_key)?.into_owned();

        Ok(Self {
            password,
            private_key,
            certificate,
        })
    }

    /// Generate a password to be used in our kdf for deriving private keys
    fn generate_password() -> QcatPassword {
        // TODO: actually generate a password
        QcatPassword(String::from("asdf"))
    }

    /// Derive a private key from our generated password
    fn derive_private_key(
        password: &QcatPassword,
    ) -> Result<PrivatePkcs8KeyDer<'static>, Box<dyn std::error::Error>> {
        // TODO: lifetimes?
        let password_bytes = password.as_bytes();
        // TODO: move 32 to const? size of ed25519 key
        // also move rounds to const
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        let derived_key_bytes = pbkdf2_hmac_array::<Sha256, 32>(password_bytes, &[], 600_000);
        let pkcs8_der_key = SigningKey::from_bytes(&derived_key_bytes).to_pkcs8_der()?;

        Ok(PrivatePkcs8KeyDer::from(pkcs8_der_key.as_bytes()).clone_key())
    }

    // Generate and sign a certificate
    fn generate_certificate(
        private_key_der: &PrivatePkcs8KeyDer,
    ) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
        // TODO: update cert params from defaults
        let cert_params = CertificateParams::new(vec![])?;
        let signing_keypair =
            KeyPair::from_pkcs8_der_and_sign_algo(private_key_der, &PKCS_ED25519)?;

        Ok(cert_params.self_signed(&signing_keypair)?.der().clone())
    }
}
