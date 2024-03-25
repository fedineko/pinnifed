use log::error;

use sfv::{
    BareItem,
    Dictionary,
    Item,
    ListEntry,
    Parser,
    SerializeValue
};

/// This structure represents labeled signature.
/// Usually, it is produced as result of parsing 'signature' header value.
pub(crate) struct Signature {
    /// Associated with signature label.
    pub label: String,
    /// Signature data, before encoding to any container.
    pub value: Vec<u8>,
}

impl Signature {
    /// Constructs new instance of signature with `label`
    /// and signature data `value`.
    pub fn new(label: &str, value: Vec<u8>) -> Self {
        Self {
            label: label.to_string(),
            value,
        }
    }

    /// This method parses 'signature' `header_value` and returns signature
    /// identified by `label`. All other signature, if any, are ignored.
    pub fn parse(header_value: &str, label: &str) -> Option<Signature> {
        let signature_dict = match Parser::parse_dictionary(
            header_value.as_ref()
        ) {
            Ok(dict) => dict,
            Err(err) => {
                error!(
                    "Failed to parse '{}' as signature dictionary: {err:?}",
                    header_value
                );
                return None;
            }
        };

        let signature_list_entry = match signature_dict.get(label) {
            None => {
                error!(
                    "No signature labeled '{label}' in header: {header_value}"
                );
                return None;
            }
            Some(value) => value
        };

        match signature_list_entry {
            ListEntry::Item(item) => {
                item.bare_item.as_byte_seq()
            }

            ListEntry::InnerList(_) => {
                error!(
                    "Unexpected type: inner list for signature '{label} in header: {header_value}'"
                );

                None
            }
        }.map(|value| Self {
            label: label.to_string(),
            value: value.clone(),
        })
    }

    /// Consumes self and produces 'signature' header value.
    pub fn into_header_value(self) -> Option<String> {
        let item = Item::new(BareItem::ByteSeq(self.value));

        let dict = Dictionary::from(
            [(self.label.clone(), ListEntry::Item(item))]
        );

        match dict.serialize_value() {
            Ok(value) => Some(value),
            Err(err) => {
                error!("Failed to serialize signature for label {}: {err:?}", self.label);
                None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::signature::Signature;

    #[test]
    fn test_signature_parsing() {
        let value = "sig1=:dGVzdCBzdHJpbmc=:";
        let signature = Signature::parse(value, "sig1");

        assert!(signature.is_some(), "Expected to find sig1 labeled signature");

        let signature = signature.unwrap();

        assert_eq!(signature.label, "sig1");

        assert_eq!(
            String::from_utf8(signature.value.clone()).ok(),
            Some("test string".into())
        );

        let header_value = signature.into_header_value();

        assert_eq!(header_value, Some(value.to_string()));
    }
}