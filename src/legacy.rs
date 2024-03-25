use std::collections::HashMap;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, error, warn};
use regex::{Regex, RegexBuilder};

use crate::{
    ConstructData,
    HttpMethod,
    SignatureProtocolHint,
    ReconstructData,
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
    key_value_regex: Regex,
}

impl Default for LegacySignatureBaseConstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacySignatureBaseConstructor {
    /// Returns new instance of legacy signature base constructor.
    pub fn new() -> Self {
        Self {
            key_value_regex: RegexBuilder::new(
                "^([a-z0-9.-]+)=\"(.+)\"$")
                .case_insensitive(true)
                .build()
                .unwrap()
        }
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
    ///
    /// TODO: make it private
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
                        // TODO: should not be set here, should be controlled by client.
                        ("Accept", ACCEPT_HEADER_VALUE.to_string()),
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

    /// Helper method to reduce boilerplate on accessing `key`
    /// in `signature_parameters` map of values extracted from
    /// 'signature' header.
    fn get_parameter<'a>(
        signature_parameters: &HashMap<&str, &'a str>,
        key: &str,
    ) -> Option<&'a str> {
        match signature_parameters.get(key) {
            None => {
                error!("'signature' header does not include '{key}' parameter");
                None
            }
            Some(value) => Some(*value)
        }
    }
}

impl SignatureBaseConstructor for LegacySignatureBaseConstructor {
    fn reconstruct(
        &self,
        verify_context: &VerifyContext,
    ) -> Option<ReconstructData> {
        let signature_header = verify_context.headers.get("signature")
            .map(|s| s.to_string())?;

        let mut headers: HashMap<&str, &str> = verify_context.headers.iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();

        let request_target = format!(
            "{} {}",
            verify_context.http_method.as_str().to_lowercase(),
            verify_context.target.path()
        );

        headers.insert("(request-target)", &request_target);

        let signature_parameters: HashMap<_, _> = signature_header.split(',')
            .map(|s| s.trim())
            .filter_map(|kv| {
                self.key_value_regex.captures(kv)
            })
            .map(|capture| (
                capture.get(1).unwrap().as_str(),
                capture.get(2).unwrap().as_str()
            ))
            .collect();

        let base = signature_parameters.get("headers")
            .map(|headers| headers.split(' ').collect::<Vec<_>>())
            .map(|hints| self.signed_string_from_headers(hints, headers))?;

        let signature = Self::get_parameter(&signature_parameters, "signature")?;

        let key_id = Self::get_parameter(&signature_parameters, "keyId")?
            .to_string();

        let key_alg = Self::get_parameter(&signature_parameters, "algorithm")
            .map(|alg| alg.to_string());

        let signature = match BASE64_STANDARD.decode(signature) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!("Failed to decode signature {:?}: {err:?}", signature);
                return None;
            }
        };

        Some(ReconstructData {
            signature_base: base,
            signature,
            key_id,
            key_alg,
        })
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

        if !sign_context.headers.contains_key("accept") {
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

        let signature_header = match construct_base_data.http_method {
            HttpMethod::Post => {
                format!(
                    "keyId=\"{}\",\
                    algorithm=\"{}\",\
                    headers=\"(request-target) host date digest\"\
                    ,signature=\"{encoded_signature}\"",
                    sign_context.key_id,
                    sign_context.key_alg,
                )
            }

            HttpMethod::Get => {
                format!(
                    "keyId=\"{}\",\
                    algorithm=\"{}\",\
                    headers=\"(request-target) host date accept\",\
                    signature=\"{encoded_signature}\"",
                    sign_context.key_id,
                    sign_context.key_alg,
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
}