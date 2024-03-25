use std::collections::HashMap;

use crate::{
    ConstructData,
    ReconstructData,
    SignatureBaseConstructor,
    SignatureHeaders,
    SignatureProtocolHint,
    SignContext,
    VerifyContext,
};

use crate::legacy::LegacySignatureBaseConstructor;
use crate::rfc9421::Rfc9421BaseConstructor;

/// Wrapper type for other signature base constructors.
/// Purpose is to select concrete constructor when needed
/// and be able to work with messages signed by different
/// incoming signature protocols.
#[derive(Debug)]
pub struct GuessingBaseConstructor {
    legacy: LegacySignatureBaseConstructor,
    rfc9421: Rfc9421BaseConstructor,
}

impl Default for GuessingBaseConstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl GuessingBaseConstructor {
    /// Constructs new instance of this type.
    pub fn new() -> Self {
        Self {
            legacy: LegacySignatureBaseConstructor::new(),
            rfc9421: Rfc9421BaseConstructor::new(),
        }
    }

    /// Helper method to select underlying constructor using given `hint`.
    /// Currently, legacy protocol is used by default, e.g., when no hint
    /// is provided.
    fn select_constructor(
        &self,
        hint: SignatureProtocolHint,
    ) -> &dyn SignatureBaseConstructor {
        if hint == SignatureProtocolHint::NoHint {
            // return more popular version and let it fail.
            return &self.legacy;
        }

        match hint {
            SignatureProtocolHint::Hint("rfc9421") => &self.rfc9421,
            _ => &self.legacy
        }
    }
}

impl SignatureBaseConstructor for GuessingBaseConstructor {
    fn reconstruct(
        &self,
        verify_context: &VerifyContext,
    ) -> Option<ReconstructData> {
        self.select_constructor(verify_context.signature_protocol_hint).reconstruct(
            verify_context
        )
    }

    fn construct(&self, sign_context: &SignContext) -> Option<ConstructData> {
        self.select_constructor(sign_context.signature_protocol_hint).construct(
            sign_context
        )
    }

    fn signature_headers(
        &self,
        sign_context: &SignContext,
        construct_base_data: ConstructData,
        signature: Vec<u8>,
    ) -> SignatureHeaders {
        self.select_constructor(sign_context.signature_protocol_hint).signature_headers(
            sign_context,
            construct_base_data,
            signature,
        )
    }

    fn protocol_hint(&self, headers: &HashMap<&str, &str>) -> SignatureProtocolHint {
        let probes: Vec<&dyn SignatureBaseConstructor> = vec![
            &self.rfc9421,
            &self.legacy,
        ];

        for probe in probes.into_iter() {
            if let SignatureProtocolHint::Hint(hint) = probe.protocol_hint(headers) {
                return SignatureProtocolHint::Hint(hint);
            }
        }

        SignatureProtocolHint::NoHint
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::ptr;
    use crate::{SignatureBaseConstructor, SignatureProtocolHint};
    use crate::wrapper::GuessingBaseConstructor;

    #[test]
    fn test_matches() {
        let headers = HashMap::from([
            ("signature-input", "some stuff here"),
            ("signature", "more stuff here")
        ]);

        let base_constructor = GuessingBaseConstructor::new();

        assert_eq!(base_constructor.protocol_hint(&headers), SignatureProtocolHint::rfc9421_hint());

        assert_eq!(
            base_constructor.rfc9421.protocol_hint(&headers),
            SignatureProtocolHint::rfc9421_hint()
        );

        assert_eq!(
            base_constructor.legacy.protocol_hint(&headers),
            SignatureProtocolHint::legacy_hint()
        );
    }
}