use std::collections::HashMap;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, error, warn};
use regex::{Regex, RegexBuilder};
use once_cell::sync::Lazy;

use crate::{
    ConstructData,
    HttpMethod,
    KeyDetails,
    KeyDetailsError,
    ReconstructData,
    SignatureProtocolHint,
    SignatureBaseConstructor,
    SignatureHeaders,
    SignContext,
    VerifyContext,
};

// TODO: get rid of this header value.
const ACCEPT_HEADER_VALUE: &str = "application/activity+json, application/ld+json";

/// This signature base constructor is used to produce base
/// according to pre-standardised versions of RFC 9421.
#[derive(Debug)]
pub struct LegacySignatureBaseConstructor {
}

struct SignatureParameters {
    signature_input: String,
    parameters: HashMap<String, String>,
}

static KEY_VALUE_REGEX: Lazy<Regex> = Lazy::new(|| RegexBuilder::new(
    "^([a-z0-9.-]+)=\"(.+)\"$")
    .case_insensitive(true)
    .build()
    .unwrap()
);

impl SignatureParameters {
    fn new(signature_input: String) -> Self {
        signature_input.match_indices(',');

        let parameters = signature_input.split(',')
            .map(|s| s.trim())
            .filter_map(|kv| {
                KEY_VALUE_REGEX.captures(kv)
            })
            .map(|capture| (
                capture.get(1).unwrap().as_str().to_owned(),
                capture.get(2).unwrap().as_str().to_owned()
            ))
            .collect();

        Self {
            parameters,
            signature_input: signature_input.clone(),
        }
    }

    pub fn input(&self) -> &str {
        &self.signature_input
    }

    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(|s| s.as_str())
    }
}

impl Default for LegacySignatureBaseConstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacySignatureBaseConstructor {
    /// Returns new instance of legacy signature base constructor.
    pub fn new() -> Self {
        Self {}
    }

    /// Helper method to produce signature base lines for `components`.
    /// Values for components are fetched from `headers` map.
    /// Returns all lines joined into single string.
    fn signed_string_from_headers(
        &self,
        components: Vec<&str>,
        headers: HashMap<&str, &str>,
    ) -> String {
        components.into_iter()
            .map(|component| format!(
                "{component}: {}", headers.get(component).unwrap())
            )
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Helper method to construct base for a give timestamp `now`, message `digest`,
    /// `target` URL accessed with `http_method`.
    fn construct_with_date(
        &self,
        now: &str,
        digest: &str,
        target: &url::Url,
        http_method: HttpMethod,
    ) -> ConstructData {
        // See:
        //  - https://github.com/w3c-ccg/http-signatures/blob/gh-pages/CGFR/index.txt
        //  - https://blog.joinmastodon.org/2018/07/how-to-make-friends-and-verify-requests/

        match http_method {
            HttpMethod::Post => {
                let signature_base = format!(
                    "(request-target): post {}\nhost: {}\ndate: {now}\ndigest: {digest}",
                    target.path(),
                    target.host().unwrap()
                );

                ConstructData {
                    signature_base,
                    http_method,
                    headers: vec![
                        ("Host", target.host().unwrap().to_string()),
                        ("Digest", digest.to_string()),
                        ("Date", now.to_string()),
                    ],
                }
            }

            HttpMethod::Get => {
                let signature_base = format!(
                    "(request-target): get {}\nhost: {}\ndate: {now}\naccept: {ACCEPT_HEADER_VALUE}",
                    target.path(),
                    target.host().unwrap()
                );

                ConstructData {
                    signature_base,
                    http_method,
                    headers: vec![
                        ("Date", now.to_string()),
                        // TODO: should not be set here, should be controlled by client.
                        ("Accept", ACCEPT_HEADER_VALUE.to_string()),
                    ],
                }
            }
        }
    }

    /// This method returns [SignatureParameters] extracted from `headers` on success,
    /// empty [Option] otherwise.
    fn signature_parameters(
        &self,
        headers: &HashMap<&str, &str>
    ) -> Option<SignatureParameters> {
        let signature_input = headers.get("signature")
            .map(|s| s.to_string())?;

        Some(SignatureParameters::new(signature_input))
    }

    /// Returns key details from parameters of earlier extracted `signature_parameters`
    fn key_details(
        &self,
        signature_parameters: &SignatureParameters,
    ) -> Result<KeyDetails, KeyDetailsError> {
        let key_id = match signature_parameters.parameter("keyId") {
            None => return Err(
                KeyDetailsError::NoKeyDetails(signature_parameters.input().to_string())
            ),
            Some(value) => value.to_string(),
        };

        // Algorithm identification label might not be present.
        let key_alg = signature_parameters.parameter("algorithm")
            .map(|alg| alg.to_string());

        Ok(KeyDetails {
            key_id,
            key_alg,
        })
    }
}

impl SignatureBaseConstructor for LegacySignatureBaseConstructor {
    fn reconstruct(
        &self,
        verify_context: &VerifyContext,
    ) -> Option<ReconstructData> {
        let signature_parameters = self.signature_parameters(&verify_context.headers)?;

        let mut headers: HashMap<&str, &str> = verify_context.headers.iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();

        let request_target = format!(
            "{} {}",
            verify_context.http_method.as_str().to_lowercase(),
            verify_context.target.path()
        );

        headers.insert("(request-target)", &request_target);

        let signature_base = signature_parameters.parameter("headers")
            .map(|headers| headers.split(' ').collect::<Vec<_>>())
            .map(|hints| self.signed_string_from_headers(hints, headers))?;

        let signature = signature_parameters.parameter("signature")?;

        let signature = match BASE64_STANDARD.decode(signature.as_bytes()) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!("Failed to decode signature {:?}: {err:?}", signature);
                return None;
            }
        };

        let key_details = match self.key_details(&signature_parameters) {
            Ok(key_details) => key_details,
            Err(err) => {
                error!("Failed to extract key details: {err:?}");
                return None;
            }
        };

        Some(
            ReconstructData {
                signature_base,
                signature,
                key_details,
            }
        )
    }

    fn construct(
        &self,
        sign_context: &SignContext,
    ) -> Option<ConstructData> {
        //  See: <https://www.rfc-editor.org/rfc/rfc2616#section-3.3>
        //
        //  All HTTP date/time stamps MUST be represented in Greenwich Mean Time
        //     (GMT), without exception. For the purposes of HTTP, GMT is exactly
        //     equal to UTC (Coordinated Universal Time). This is indicated in the
        //     first two formats by the inclusion of "GMT" as the three-letter
        //     abbreviation for time zone, and MUST be assumed when reading the
        //     asctime format.
        let now = sign_context.headers.get("date")
            .map(|s| s.to_string())
            .or_else(||
                Some(
                    chrono::Utc::now()
                        .format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string()
                )
            )?;

        let digest = match sign_context.headers.get("digest") {
            None if sign_context.http_method == HttpMethod::Post => {
                error!("'digest' header must be set before calling legacy construct()");
                return None;
            }
            None => "",
            Some(value) => *value,
        };

        if !sign_context.headers.contains_key("accept") &&
            sign_context.http_method == HttpMethod::Get
        {
            error!("'accept' header must be set before calling legacy construct()");
            return None;
        }

        Some(
            self.construct_with_date(&now, digest, sign_context.target, sign_context.http_method)
        )
    }

    fn signature_headers(
        &self,
        sign_context: &SignContext,
        construct_base_data: ConstructData,
        signature: Vec<u8>,
    ) -> SignatureHeaders {
        let encoded_signature = BASE64_STANDARD.encode(signature);

        // HACK: legacy base constructor uses a slightly different
        //       labels for supported algorithms.
        let key_alg = match sign_context.key_alg {
            "rsa-v1_5-sha256" => "rsa-sha256",
            _ => sign_context.key_alg,
        };

        let signature_header = match construct_base_data.http_method {
            HttpMethod::Post => {
                format!(
                    "keyId=\"{}\",\
                    algorithm=\"{}\",\
                    headers=\"(request-target) host date digest\"\
                    ,signature=\"{encoded_signature}\"",
                    sign_context.key_id,
                    key_alg,
                )
            }

            HttpMethod::Get => {
                format!(
                    "keyId=\"{}\",\
                    algorithm=\"{}\",\
                    headers=\"(request-target) host date accept\",\
                    signature=\"{encoded_signature}\"",
                    sign_context.key_id,
                    key_alg,
                )
            }
        };

        debug!("Signature header: {}", signature_header);

        let headers = [
            construct_base_data.headers,
            vec![("Signature", signature_header)]
        ].concat();

        SignatureHeaders {
            headers,
        }
    }

    fn protocol_hint(&self, headers: &HashMap<&str, &str>) -> SignatureProtocolHint {
        match headers.contains_key("signature") {
            true => SignatureProtocolHint::Hint("pre-rfc9421"),
            false => SignatureProtocolHint::NoHint,
        }
    }

    fn key_details_from_headers(
        &self,
        headers: &HashMap<&str, &str>,
    ) -> Result<KeyDetails, KeyDetailsError> {
        let signature_parameters = match self.signature_parameters(headers) {
            None => return Err(KeyDetailsError::UnknownSignature),
            Some(value) => value,
        };

        self.key_details(&signature_parameters)
    }
}