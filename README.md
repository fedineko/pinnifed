# What?

This library is used in Fedineko project to sign or verify requests.

Message signing and signature verification itself is done in `puprik` 
and related libraries. This library just constructs signature base 
for signature verification or signing purposes.

`pinnifed` is not intended for general use as API is not stable plus focus
here is more on needs of Fedineko project, e.g. lousy signature verification
of incoming messages rather than solid sign/verify framework.

Somewhat supported are:
* RFC 9421: HTTP Message Signatures https://www.rfc-editor.org/rfc/rfc9421.html
* pre-RFC 9421 version known as "HTTP Signatures" which is more popular
  currently, it is used by default in `pinnifed` and is kind of tested by 
  running `octofedi` (yet another Fedineko component) for a few months.

Emphasis is on "somewhat", library lacks a lot of features required by standard:
* Referencing request headers in response signature with `req` parameter 
  is not possible.
* Components such as `@status`, `@query-param`, `@request-target` are not
  supported.
* Logic is less strict as required by standard.
* List goes on.
* Legacy constructor has bare minimum functionality as well.

Some of these above are likely to be addressed later, others are not.

# Usage

First, signature base constructor is instantiated.

```rust
use pinnifed::default_signature_base_constructor;

let base_constructor = default_signature_base_constructor();
```

To verify a signature of message or sign the message context needs
to be built for that message.

## Signature verification

Context encapsulates request data such as:
* `headers` - this library expects header names in lower case.
             Library supposedly is not HTTP client specific,
             so headers are passed as string values.
* `target` - URL request was sent to, e.g., `https://server.tld/path/to/actor`
* `http_method` - signature base construction depends or at least might
                 depend on HTTP method, e.g., to select different components.
* `signature_protocol_hint` - hints library to use specific signature base
                 construction protocol. Could be set to `NoHint` and library
                 will try it's best to choose more suitable one.

```rust
use pinnifed::{HttpMethod, VerifyContext};

let verify_context = VerifyContext {
    headers: HashMap::from([
        ("signature-input", ...),
        ("signature", "sig1=:dGVzdCBzdHJpbmc=:"),
        ...
    ]),
    target: &target,
    http_method: HttpMethod::Post,
    signature_protocol_hint: SignatureProtocolHint::NoHint
};

let rsbd = base_constructor.reconstruct(&verify_context).unwrap();
```
At this stage signature value is extracted from message, signature base is constructed
and signature is ready for verification.

```rust
// fictional key_registry provides public key for the given ID.

let public_key = key_registry.get(rsbd.key_id, rsbd.key_alg);

public_key.verify(rsbd.signature_base.as_bytes(), &rsbd.signature);
```

## Signing

Producing signature is a bit more complicated process as it is split
into multiple steps:
- Signature base is constructed by `pinnifed`.
- Signature base is signed by caller.
- Finally, signature headers are produced with given signature by `pinnifed`.

```rust
// Step 1: construct signature base

let sign_context = SignContext {
    headers: HashMap::from([...]),
    ...
    key_id: private_key.id.as_str(),
    key_alg: private_key.sign_algorithm.as_str(),
    signature_protocol_hint: SignatureProtocolHint::legacy_hint()
};

let csbd = base_constructor.construct(&sign_context).unwrap();
```

First step is similar to signature verification flow. 

Next step is where the actual signing magic happens outside of `pinnifed`:

```rust
// Step 2: produce signature for signature base using private key

let signature = private_key.sign(
    base_data.signature_base.as_bytes()
);
```

Finally, headers need to be produced from signature base and signature:

```rust
// Step 3: passing signature data to base constructor to wrap it into header.

let signature_headers = base_constructor.signature_headers(
    sign_context,
    csbd,
    signature,
);
```

`signature_headers` in the snippet above is instance of `SignatureHeaders`
object that wraps map of new headers (signature related) so these could be
merged with all other headers before sending request.

# License

MIT or Apache 2.0.
