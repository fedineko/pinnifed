use std::collections::HashMap;

use itertools::Itertools;
use log::{error, warn};

use sfv::{
    BareItem,
};

use crate::{
    ConstructData,
    HttpContext,
    HttpMethod,
    KeyDetails,
    KeyDetailsError,
    ReconstructData,
    SignatureBaseConstructor,
    SignatureHeaders,
    SignatureProtocolHint,
    SignContext,
    VerifyContext,
};

use crate::signature::Signature;
use crate::signature_input::SignatureInput;

/// Basic implementation of RFC 9421 for message signatures.
/// "Basic" means a lot is missing and certainly some things
/// are not as strict as prescribed by spec.
#[derive(Debug)]
pub struct Rfc9421BaseConstructor {}

impl Rfc9421BaseConstructor {
    pub fn new() -> Self {
        // Keeping it for compatibility purposes
        Self {}
    }

    /// Helper method to construct signature base line for `component`,
    /// value for it is fetched from `context`.
    ///
    /// Returns empty [Option] if line could bot be produced. This
    /// happens either because there is issues with signature
    /// components declaration or because some components are not
    /// supported.
    fn component_to_signature_base_line(
        component: &str,
        context: &impl HttpContext,
    ) -> Option<String> {
        match component {
            "@method" => return Some(
                format!("\"@method\": {}", context.http_method().as_str())
            ),

            "@target-uri" => return Some(
                format!("\"@target-uri\": {}", context.target().as_str())
            ),

            "@path" => return Some(
                format!("\"@path\": {}", context.target().path())
            ),

            "@authority" => return context.target().host_str()
                .map(|host| format!("\"@authority\": {}", host)),

            "@scheme" => return Some(
                format!("\"@scheme\": {}", context.target().scheme())
            ),

            "@query" => return context.target().query()
                .map(|query| format!("\"@query\": {query}")),

            // @request-target, @query-param, @status are ignored
            "@request-target" | "@query-param" | "@status" => {
                warn!("Component '{component}' is not supported and was ignored");
                return None;
            }

            _ => { /* fall through */ }
        }

        context.headers().get(component)
            .map(|value| format!("\"{component}\": {value}"))
    }

    /// Helper method to construct signature base from given lists of
    /// `components`, `parameters` and `sign_context`.
    fn construct_with_parameters(
        &self,
        components: Vec<&str>,
        sign_context: &SignContext,
        parameters: Vec<(String, BareItem)>,
    ) -> Option<ConstructData> {
        let component_lines = components.iter()
            .filter_map(|component| Self::component_to_signature_base_line(
                component,
                sign_context,
            ))
            .collect();

        let signature_input = SignatureInput::new("pf-sig1", components, parameters);
        let signature_params = signature_input.to_signature_params()?;
        let signature_input_header = signature_input.serialize()?;

        Some(ConstructData {
            signature_base: Self::merge_to_signature_base(component_lines, &signature_params),
            http_method: sign_context.http_method,
            headers: vec![
                ("signature-input", signature_input_header)
            ],
        })
    }

    /// Helper method to merge `component_lines` of signature base
    /// and `@signature-params` line constructed from `signature_params_value`
    /// argument.
    fn merge_to_signature_base(
        component_lines: Vec<String>,
        signature_params_value: &str,
    ) -> String {
        let signature_params = format!("\"@signature-params\": {signature_params_value}");

        [component_lines, vec![signature_params]]
            .concat()
            .into_iter()
            .intersperse('\n'.to_string())
            .collect()
    }

    /// Helper method to convert list of `components` to list of
    /// signature base lines. `http_context` is passed for usage
    /// further down call chain.
    fn components_to_component_base_line_vec(
        components: &[String],
        http_context: &impl HttpContext,
    ) -> Vec<String> {
        components.iter()
            .filter_map(|component|
                Self::component_to_signature_base_line(
                    component, http_context,
                )
            )
            .collect::<Vec<_>>()
    }
}

impl SignatureBaseConstructor for Rfc9421BaseConstructor {
    fn reconstruct(
        &self,
        verify_context: &VerifyContext,
    ) -> Option<ReconstructData> {
        let signature_input_header = verify_context.headers.get("signature-input")?;
        let signature_header = verify_context.headers.get("signature")?;

        let signature_input = SignatureInput::parse(signature_input_header)?;
        let signature = Signature::parse(signature_header, &signature_input.label)?;

        let key_alg = signature_input.parameter_as_str("alg")
            .map(|alg| alg.to_string());

        let key_id = signature_input.parameter_as_str("keyid")?
            .to_string();

        let component_lines = Self::components_to_component_base_line_vec(
            &signature_input.components,
            verify_context,
        );

        let signature_params = signature_input.to_signature_params()?;

        let base = Self::merge_to_signature_base(component_lines, &signature_params);

        let key_details = KeyDetails {
            key_id,
            key_alg,
        };

        Some(
            ReconstructData {
                signature_base: base,
                signature: signature.value,
                key_details,
            }
        )
    }

    fn construct(
        &self,
        sign_context: &SignContext,
    ) -> Option<ConstructData> {
        let now = chrono::Utc::now();

        let parameters = vec![
            ("created", BareItem::Integer(now.timestamp())),
            ("alg", BareItem::String(sign_context.key_alg.to_string())),
            ("keyid", BareItem::String(sign_context.key_id.to_string())),
        ].into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        match sign_context.http_method {
            HttpMethod::Post => {
                if !sign_context.headers.contains_key("content-digest") {
                    error!("'content-digest' header must be set");
                    return None;
                }

                self.construct_with_parameters(
                    vec!["@method", "@path", "@authority", "content-digest"],
                    sign_context,
                    parameters,
                )
            }

            HttpMethod::Get => {
                self.construct_with_parameters(
                    vec!["@method", "@path", "@authority", "accept"],
                    sign_context,
                    parameters,
                )
            }
        }
    }

    fn signature_headers(
        &self,
        _sign_context: &SignContext,
        construct_base_data: ConstructData,
        signature: Vec<u8>,
    ) -> SignatureHeaders {
        let signature_object = Signature::new("pf-sig1", signature);

        let signature_headers = signature_object.into_header_value()
            .map(|header_value| vec![("signature", header_value)])
            .unwrap_or_default();

        let headers = [
            construct_base_data.headers,
            signature_headers,
        ].concat();

        SignatureHeaders {
            headers,
        }
    }

    fn protocol_hint(&self, headers: &HashMap<&str, &str>) -> SignatureProtocolHint {
        if headers.contains_key("signature-input") && headers.contains_key("signature") {
            SignatureProtocolHint::Hint("rfc9421")
        } else {
            SignatureProtocolHint::NoHint
        }
    }

    fn key_details_from_headers(
        &self,
        headers: &HashMap<&str, &str>,
    ) -> Result<KeyDetails, KeyDetailsError> {
        let signature_input_header = match headers.get("signature-input") {
            None => return Err(KeyDetailsError::UnknownSignature),
            Some(value) => value,
        };

        let signature_input = match SignatureInput::parse(signature_input_header) {
            None => return Err(
                KeyDetailsError::MalformedSignature(signature_input_header.to_string())
            ),
            Some(value) => value,
        };

        let key_id = match signature_input.parameter_as_str("keyid") {
            None => return Err(
                KeyDetailsError::MalformedSignature(signature_input_header.to_string())
            ),
            Some(value) => value.to_string()
        };

        let key_alg = signature_input.parameter_as_str("alg")
            .map(|s| s.to_string());

        Ok(
            KeyDetails {
                key_id,
                key_alg,
            }
        )
    }
}

impl Default for Rfc9421BaseConstructor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use url::Url;

    use crate::{HttpMethod, SignatureProtocolHint, SignContext, VerifyContext};
    use crate::rfc9421::Rfc9421BaseConstructor;
    use crate::SignatureBaseConstructor;

    #[test]
    fn test_signature_create() {
        let base_constructor = Rfc9421BaseConstructor::new();

        // Test request data:
        //   POST /foo?param=Value&Pet=dog HTTP/1.1
        //   Host: example.com
        //   Date: Tue, 20 Apr 2021 02:07:55 GMT
        //   Content-Type: application/json
        //   Content-Digest: sha-512=:c2hhLTUxMg==:
        //   Content-Length: 18

        let target = Url::parse("https://example.com/foo?param=Value&Pet=dog").unwrap();

        let original_headers = HashMap::from([
            ("content-digest", "sha-512=:c2hhLTUxMg==:"),
        ]);

        let sign_context = SignContext {
            headers: original_headers.clone(),
            target: &target,
            http_method: HttpMethod::Post,
            key_id: "test-key-rsa-pss",
            key_alg: "rsa-sha256",
            signature_protocol_hint: SignatureProtocolHint::rfc9421_hint(),
        };

        let signature = "test string".as_bytes().to_vec();

        let construct_data = base_constructor.construct(&sign_context).unwrap();
        let constructed_base = construct_data.signature_base.clone();

        let signature_headers = base_constructor.signature_headers(
            &sign_context, construct_data, signature.clone(),
        );

        let headers: HashMap<_, _> = signature_headers.headers.iter()
            .map(|(k, v)| (*k, v.as_str()))
            .chain(original_headers)
            .collect();

        let verify_context = VerifyContext {
            headers,
            target: &target,
            http_method: HttpMethod::Post,
            signature_protocol_hint: SignatureProtocolHint::rfc9421_hint(),
        };

        let reconstruct_base = base_constructor.reconstruct(
            &verify_context
        ).unwrap();

        assert_eq!(reconstruct_base.signature, signature);
        assert_eq!(reconstruct_base.key_details.key_alg, Some(sign_context.key_alg.to_string()));
        assert_eq!(reconstruct_base.signature_base, constructed_base);
    }

    #[test]
    fn test_signature_base_recreate() {
        let base_constructor = Rfc9421BaseConstructor::new();
        // Test request data:
        //   POST /foo?param=Value&Pet=dog HTTP/1.1
        //   Host: example.com
        //   Date: Tue, 20 Apr 2021 02:07:55 GMT
        //   Content-Type: application/json
        //   Content-Digest: sha-512=:c2hhLTUxMg==:
        //   Content-Length: 18
        //   Signature-Input: sig1=("@method" "@authority" "@path" \
        //     "content-digest" "content-length" "content-type")\
        //     ;created=1618884473;keyid="test-key-rsa-pss"
        //   Signature: sig1=:dGVzdCBzdHJpbmc=:
        let signature_input = "sig1=(\
                \"@method\" \"@authority\" \"@path\" \
                \"content-digest\" \"content-length\" \"content-type\");\
                created=1618884473;keyid=\"test-key-rsa-pss\"";

        let target = Url::parse("https://example.com/foo?param=Value&Pet=dog").unwrap();

        let verify_context = VerifyContext {
            headers: HashMap::from([
                ("signature-input", signature_input),
                ("signature", "sig1=:dGVzdCBzdHJpbmc=:"),
                ("content-digest", "sha-512=:c2hhLTUxMg==:"),
                ("content-length", "18"),
                ("content-type", "application/json"),
            ]),
            target: &target,
            http_method: HttpMethod::Post,
            signature_protocol_hint: SignatureProtocolHint::rfc9421_hint(),
        };

        let reconstruct_data = base_constructor.reconstruct(&verify_context);

        assert!(reconstruct_data.is_some());

        let reconstruct_data = reconstruct_data.unwrap();

        println!("{}", reconstruct_data.signature_base);

        assert_eq!(String::from_utf8(reconstruct_data.signature).unwrap(), "test string".to_string());

        assert_eq!(reconstruct_data.signature_base, "\
            \"@method\": POST\n\
            \"@authority\": example.com\n\
            \"@path\": /foo\n\
            \"content-digest\": sha-512=:c2hhLTUxMg==:\n\
            \"content-length\": 18\n\
            \"content-type\": application/json\n\
            \"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \
            \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\""
        )
    }
}