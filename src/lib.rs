use std::collections::HashMap;

use crate::SignatureProtocolHint::Hint;
use crate::wrapper::GuessingBaseConstructor;

pub mod legacy;
pub mod rfc9421;
pub mod wrapper;

mod signature;
mod signature_input;

/// Specifies HTTP method for which signature is generated.
/// Methods might have different components in signature.
#[derive(Copy, Clone, PartialEq)]
pub enum HttpMethod {
    Post,
    Get,
}

impl HttpMethod {
    /// Return self as upper case string literal.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Get => "GET",
        }
    }
}

/// This enumeration is used to hint which signature
/// protocol to try.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SignatureProtocolHint {
    NoHint,
    Hint(&'static str),
}

impl SignatureProtocolHint {
    pub fn rfc9421_hint() -> Self {
        Hint("rfc9421")
    }

    pub fn legacy_hint() -> Self {
        Hint("pre-rfc9421")
    }
}

/// Represents key details used to select appropriate key
/// to verify messages.
pub struct KeyDetails {
    /// ID of the key to use for signature verification.
    key_id: String,
    /// Algorithm of the key to us for signature verification.
    key_alg: Option<String>,
}

impl KeyDetails {
    /// Returns key ID.
    pub fn id(&self) -> &str {
        &self.key_id
    }

    /// Returns key algorithm to use as a hint
    /// when loading key.
    pub fn alg(&self) -> Option<&str> {
        self.key_alg.as_ref()
            .map(|s| s.as_str())
    }
}

/// Context shared between [SignContext] and [VerifyContext].
pub trait HttpContext {
    /// Returns headers captured in context.
    fn headers(&self) -> &HashMap<&str, &str>;
    /// Returns target URL, request's host and path together.
    fn target(&self) -> &url::Url;
    /// Returns HTTP method for which signature is produced or verified.
    fn http_method(&self) -> HttpMethod;
    /// Returns hint to assists in selection of protocol.
    fn signature_protocol_hint(&self) -> SignatureProtocolHint;
}

/// This structure is used to capture context for signing purposes.
pub struct SignContext<'a> {
    /// Request headers. Nothing stops from passing response headers,
    /// but response signing is not well-supported by this library.
    /// `headers` MUST have lowercase keys.
    // TODO: needs to be multimap here and elsewhere in this module.
    pub headers: HashMap<&'a str, &'a str>,
    /// Request target, including host and path
    pub target: &'a url::Url,
    /// Request HTTP method, one of a few supported by library.
    /// For the most outgoing requests it is GET.
    pub http_method: HttpMethod,
    /// ID of key intended to sign a message.
    pub key_id: &'a str,
    /// Algorithm used to sign a message.
    pub key_alg: &'a str,
    /// Signature protocol hint.
    pub signature_protocol_hint: SignatureProtocolHint,
}

impl HttpContext for SignContext<'_> {
    fn headers(&self) -> &HashMap<&str, &str> {
        &self.headers
    }

    fn target(&self) -> &url::Url {
        self.target
    }

    fn http_method(&self) -> HttpMethod {
        self.http_method
    }

    fn signature_protocol_hint(&self) -> SignatureProtocolHint {
        self.signature_protocol_hint
    }
}

/// This structure is used to capture context for verification purposes.
pub struct VerifyContext<'a> {
    /// Request headers. Nothing stops from passing response headers,
    /// but response signing is not well-supported by this library.
    /// `headers` MUST have lowercase keys.
    // TODO: needs to be multimap here and elsewhere in this module.
    pub headers: HashMap<&'a str, &'a str>,
    /// Request target, including host and path
    pub target: &'a url::Url,
    /// Request HTTP method, one of a few supported by library.
    /// For the most incoming requests it is POST.
    pub http_method: HttpMethod,
    /// Signature protocol hint.
    pub signature_protocol_hint: SignatureProtocolHint,
}

impl HttpContext for VerifyContext<'_> {
    fn headers(&self) -> &HashMap<&str, &str> {
        &self.headers
    }

    fn target(&self) -> &url::Url {
        self.target
    }

    fn http_method(&self) -> HttpMethod {
        self.http_method
    }

    fn signature_protocol_hint(&self) -> SignatureProtocolHint {
        self.signature_protocol_hint
    }
}

/// This structure is returned on base reconstruct call.
pub struct ReconstructData {
    /// Reconstructed base for signature verification.
    pub signature_base: String,
    /// Extracted from request data signature.
    /// It is actual signature, not Base64 encoded value.
    pub signature: Vec<u8>,
    /// Details of key to use for signature verification.
    pub key_details: KeyDetails,
}

/// This structure is returned on base construct call.
pub struct ConstructData {
    /// Constructed base for signing.
    pub signature_base: String,
    /// HTTP method used to select components for signing
    pub http_method: HttpMethod,
    /// New headers produces so far. These are lowercase.
    pub headers: Vec<(&'static str, String)>,
}

/// This structure returned on signature_headers() call.
/// Purpose is to keep new headers used for signature related data.
pub struct SignatureHeaders {
    pub headers: Vec<(&'static str, String)>,
}

/// Error produced when extracting key details from signature.
#[derive(Debug)]
pub enum KeyDetailsError {
    /// Could not find signature details, either it does not exist
    /// or protocol/format is not supported.
    UnknownSignature,

    /// Signature for supported protocol/spec does exist
    /// but something is not right and parser fails.
    MalformedSignature(String),

    /// Signature seems to match known spec but base constructor
    /// failed to extract key details which usually means there is
    /// some issue with signature data itself.
    NoKeyDetails(String),
}

/// This trait defines methods all base constructors need to implement.
pub trait SignatureBaseConstructor: std::fmt::Debug {
    /// Takes `verify_context` and attempts to construct signature base using it.
    /// Returns [ReconstructData] wrapped to Option on success, empty [Option]
    /// otherwise.
    fn reconstruct(
        &self,
        verify_context: &VerifyContext,
    ) -> Option<ReconstructData>;

    /// Takes `sign_context` and attempts to construct signature base using it.
    /// Returns [ConstructData] wrapped to Option on success, empty [Option]
    /// otherwise.
    ///
    /// This is first step to produce signature, should be followed by
    /// [signature_headers()] on producing signature.
    fn construct(
        &self,
        sign_context: &SignContext,
    ) -> Option<ConstructData>;

    /// This method produces new headers with signature to pass with request.
    /// It applies `signature` and earlier produced `construct_base_data` to
    /// finalise signing process. `sign_context` needs to match context that
    /// was passed to [construct()] before.
    fn signature_headers(
        &self,
        sign_context: &SignContext,
        construct_base_data: ConstructData,
        signature: Vec<u8>,
    ) -> SignatureHeaders;

    /// Checks if `headers` match supported signature protocol.
    /// If yes, returns appropriate `SignatureProtocolHint::Hint`
    /// used to select sign or verify implementations.
    fn protocol_hint(&self, headers: &HashMap<&str, &str>) -> SignatureProtocolHint;

    /// Returns key details from `headers` if any so caller could
    /// obtain public key for verification purposes.
    fn key_details_from_headers(
        &self,
        headers: &HashMap<&str, &str>
    ) -> Result<KeyDetails, KeyDetailsError>;
}

/// This function returns default signature base constructor.
/// In theory, it should be the best choice for consuming code.
pub fn default_signature_base_constructor() -> impl SignatureBaseConstructor + Sync + Send {
    GuessingBaseConstructor::new()
}