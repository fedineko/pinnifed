use log::{error, warn};

use sfv::{
    BareItem,
    Dictionary,
    InnerList,
    Item,
    List,
    ListEntry,
    Parameters,
    Parser,
    SerializeValue
};

/// This structure represents parse result of 'signature-input' header value.
pub(crate) struct SignatureInput {
    /// Signature label reference.
    pub label: String,
    /// Components to construct base.
    pub components: Vec<String>,
    /// Structured Fields representation of the header value.
    pub inner_list: InnerList,
}

impl SignatureInput {
    /// Constructs new instance of this type from given `label`,
    /// vector of string slices for `components` and vector of
    /// `parameters` tuples of parameter name and value for it.
    pub fn new(
        label: &str,
        components: Vec<&str>,
        parameters: Vec<(String, BareItem)>,
    ) -> Self {
        let components: Vec<_> = components.into_iter()
            .map(|s| s.to_string())
            .collect();

        let inner_list_items = components.iter()
            .map(|item| Item::new(
                BareItem::String(item.clone()))
            )
            .collect();

        let inner_list_parameters = Parameters::from_iter(parameters);
        let inner_list = InnerList::with_params(inner_list_items, inner_list_parameters);

        Self {
            label: label.to_string(),
            components,
            inner_list,
        }
    }

    /// This method parses `header_value` of 'signature-input' header
    /// and produces instance of this type.
    pub fn parse(
        header_value: &str
    ) -> Option<SignatureInput> {
        let signature_input_dict = match Parser::parse_dictionary(
            header_value.as_bytes()
        ) {
            Ok(dict) => dict,
            Err(err) => {
                error!(
                    "Failed to parse '{}' as signature input dictionary: {err:?}",
                    header_value
                );

                return None;
            }
        };

        let (label, inner_list, components) = signature_input_dict.first()
            .and_then(|(label, list_entry)| match list_entry {
                ListEntry::InnerList(inner_list) => Some(
                    (
                        label,
                        inner_list,
                        Self::inner_list_to_string_vec(inner_list),
                    )
                ),
                _ => {
                    error!("Expected inner list as value for {label}, got: {list_entry:?}");
                    None
                }
            })?;

        Some(
            SignatureInput {
                label: label.clone(),
                components,
                inner_list: inner_list.clone(),
            }
        )
    }

    /// This method consumes self and serializes into string value
    /// expected for 'signature-input'.
    pub fn serialize(self) -> Option<String> {
        let dict = Dictionary::from([
            (self.label.clone(), ListEntry::InnerList(self.inner_list))
        ]);

        match dict.serialize_value() {
            Ok(value) => Some(value),

            Err(err) => {
                error!(
                    "Failed to serialize sinature input for '{}': {err:?}",
                    self.label
                );

                None
            }
        }
    }

    #[cfg(test)]
    fn parameter(&self, name: &str) -> Option<&BareItem> {
        self.inner_list.params.get(name)
    }

    /// Returns string parameter identified by `key`.
    /// If `key` do not exist or type is not string, then
    /// empty [Option] is returned.
    pub(crate) fn parameter_as_str(&self, key: &str) -> Option<&str> {
        match self.inner_list.params.get(key) {
            None => {
                warn!(
                    "Expected '{key}' parameter for signature '{}': {:?}",
                    self.label, self.inner_list,
                );

                None
            }

            Some(value) => {
                match value.as_str() {
                    None => {
                        error!(
                            "Expected string parameter '{key}' \
                            for signature '{}': {value:?}",
                            self.label,
                        );
                        None
                    }
                    Some(value) => Some(value),
                }
            }
        }
    }

    /// Helper method to convert [InnerList] into vector of strings.
    /// Useful for dealing with components.
    fn inner_list_to_string_vec(
        inner_list: &InnerList,
    ) -> Vec<String> {
        inner_list.items.iter()
            .filter_map(|item| item.bare_item.as_str())
            .map(|component| component.to_string())
            .collect::<Vec<_>>()
    }

    /// This method produces string suitable for passing as `@signature-params`
    /// value of signature base.
    pub(crate) fn to_signature_params(&self) -> Option<String> {
        // TODO: migrate to RefListSerializer
        let list: List = vec![ListEntry::InnerList(self.inner_list.clone())];

        match list.serialize_value() {
            Ok(value) => Some(value),
            Err(err) => {
                error!(
                    "Failed to serialize input for label '{}' into @signature-params input: {err:?}",
                    self.label
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use sfv::BareItem;
    use crate::signature_input::SignatureInput;

    #[test]
    fn test_basic_signature_input_parsing() {
        let value = "\
            sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"cache-control\");\
            created=1618884475;keyid=\"test-key-rsa-pss\"";

        let input = SignatureInput::parse(value).unwrap();

        assert_eq!(input.label, "sig1");

        assert_eq!(
            input.components,
            vec!["@method", "@target-uri", "@authority", "content-digest", "cache-control"]
        );

        assert_eq!(
            input.parameter("created"),
            Some(BareItem::Integer(1618884475)).as_ref()
        );

        assert_eq!(
            input.parameter("keyid"),
            Some(BareItem::String("test-key-rsa-pss".into())).as_ref()
        );
    }
}