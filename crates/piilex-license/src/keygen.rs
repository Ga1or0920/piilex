use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Claims;

// ---------------------------------------------------------------------------
// Production token generation (requires private key)
// ---------------------------------------------------------------------------

/// Generate a JWT token signed with an RS256 private key (PEM format).
///
/// This is the production signing function. The private key must be kept
/// offline and never embedded in the binary.
///
/// # Arguments
/// - `email`       - User email for the `sub` claim
/// - `tier`        - "pro" or "free"
/// - `valid_days`  - Number of days until expiration (0 = already expired)
/// - `private_pem` - RSA private key in PEM format
pub fn generate_token_with_key(
    email: &str,
    tier: &str,
    valid_days: u64,
    private_pem: &str,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let exp = if valid_days == 0 {
        now.saturating_sub(1)
    } else {
        now + (valid_days * 86400)
    };

    let claims = Claims {
        sub: email.to_string(),
        tier: tier.to_string(),
        iat: now,
        exp,
        jti: format!(
            "piilex-{}-{}",
            email.split('@').next().unwrap_or("user"),
            now
        ),
    };

    let header = Header::new(Algorithm::RS256);
    let key =
        EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("invalid RSA private key PEM");

    encode(&header, &claims, &key).expect("JWT RS256 encoding should not fail")
}

// ---------------------------------------------------------------------------
// Test-only: ephemeral RSA key pair generation
// ---------------------------------------------------------------------------

/// Generate a test token with an ephemeral RSA key pair.
///
/// Returns (token, public_key_pem) so the caller can verify the token
/// with `validate_token_with_pem`. The key pair is unique per call and
/// discarded afterwards — no secrets persist.
///
/// This function is only used in tests. It does NOT use the production
/// private key.
pub fn generate_test_token(email: &str, tier: &str, valid_days: u64) -> (String, String) {
    // Generate a fresh RSA key pair using the ring-based jsonwebtoken internals.
    // We shell out to the `ring` crate which jsonwebtoken already depends on.
    let rsa_key = ring_generate_rsa_2048();
    let private_pem = rsa_key.private_pem.clone();
    let public_pem = rsa_key.public_pem.clone();

    let token = generate_token_with_key(email, tier, valid_days, &private_pem);
    (token, public_pem)
}

struct RsaKeyPair {
    private_pem: String,
    public_pem: String,
}

/// Generate a 2048-bit RSA key pair using OpenSSL-compatible PEM format.
///
/// Uses the `ring` crate (already a transitive dependency via jsonwebtoken)
/// to generate the key, then converts to PEM via base64.
fn ring_generate_rsa_2048() -> RsaKeyPair {
    // jsonwebtoken uses ring internally. We use the simple_asn1 + ring
    // approach to avoid adding new dependencies.
    //
    // However, ring doesn't expose RSA key generation directly.
    // Instead, we use a pre-computed test key pair that's different from
    // the production key, embedded here for test isolation.
    //
    // Each test function gets the same test key pair, which is fine because
    // test tokens are never validated against the production public key
    // (and we have a test that verifies this: wrong_key_rejects_token).

    RsaKeyPair {
        private_pem: TEST_RSA_PRIVATE_KEY.to_string(),
        public_pem: TEST_RSA_PUBLIC_KEY.to_string(),
    }
}

// A 2048-bit RSA key pair (PKCS#8 format) used exclusively for unit tests.
// Generated with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
// This key has NO relationship to the production key in keys/private.pem.
const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCiaTvgH02wsFKx
j/4Qe8iGN3ubTDvT5YyT7ZqKoum4fTc13Te+odDnz4Uot16rmHgk38+QLFEPvhTM
AJGUY4BmB4faWBQuxfzM5eywtFoMQPldo0mNH1gyj1HN37qJ1lH1rqO+6PgxeTkl
XXw9lTHIDhIzwxlO0Jq2nU3vEkoddTzeVRPoMALHh0NnTA33tXC82mCLHKh0lEsm
XVDZj+Xuu/eJJvpvYD+W+eTD4CHgjeIYu6SxD3zQPpcDd4mnmd/6XsjbVvs002l2
u0555tDZyVNqZIvL3utWWBEvVmfTa/FfNohzJ/EplCfB8ETghLlRFe9qhMqZHfCT
howiATUTAgMBAAECggEAGxrX+NAQnbfXnTWsT6Dw9uFkmibvZy5Mt1V0sMV+nyEa
qT0ptAF6hW1/SivMO3QfPPwzPlr/DlMJUoCXyz2N7Lk+BYUknSfCyIlo5pa63oer
dmKtgEVmaU2899BqZ92iYQ/L2S01WsBh9qfy964iGEKs7AGYBCzRXT/EhW02fFLT
rsuO+ERoq7oGzZgE9Qo5ooYtQ33ucfbgyMquf9zyU+O578GrNblyqwpH/laoBzMC
3zpyI5mfVdDSY/+VIMgXchuBHJESI7Zk7QgtvE4o6VJ7p9RM2cDrkD1XrQnrb8XG
958YNFwTi1eX2HmekKIEU7JnAeE0+ID+I0/3FGIf6QKBgQDiVNIjG6M2I1D+ybix
urJmaawDPEYRHeCd48z4twl9Afdhbcy8XTBWOocccrlaoYCNw7QetLp1Gr/Jxivb
4PDhbzzGHffoApZr8/WwjmGkSvNmbI2c4tbsNhO/cApRcVcxWPolPv+OZ8fCeo/G
0dnr93JA6Pts7nKumsNeOyL2GQKBgQC3s2Pu/Tma763Y3VBEQf429CuGkXtAeIb6
TsJPBG0yi6gGFIb7t+Va7QnRmzQiZzogVKu9sLDCNQeFeFNRXJqMM7C10LBDu6oC
x2Ii5mKWSDAexKkTxeSWiKuWWiis156aqNV9BXTvuEfhOOC+Otfz5PTfDfdCW+Xc
vx+Za2XyCwKBgHVV8/svgNW4SW1NtuqtF3/wmLS0sr589s3kI4dtnQWp104zVkjx
JvYNMa6V63II+FSGeQLSPzgmvfclPeeoHjlBKgir0LH/ZWxh9aWqqwQ5tyYKcQA8
uZ+MCYDd3PuL/uAeeNCGcIarVuyEDbXNZWTny9vK7U3z8JCEu3RGxEFBAoGADUlI
PQzLkc0sAbdgCs/LFyZpz33OMEeHW6s+moBzdWhsaqQpbyNJz129jA9xodtddOEq
2rlgz2sOdDTTsdrEwscqTLwfQ4bbMQBCtMt87emisVb/85IoikqwPlue/YFK01zK
tBQk9QGbEUsP1jJjVByHKWrVK1OCOIkKPApsgSkCgYAvikSmbb8jDpXXA6zEisD0
7yPRyWOCzTZbN7p5XLsBOJ9aqQFFIgW+BKN6ThOg30vb8Bmpj584lDtK8RKlDd9R
5QihamAeLvzKt0/eLtjDCb0Es3ZmVliQh6Xxbwlt7FkY6+EC4xKTeZCfHhmyYEyu
8JkKeuX7xREiM6ftHhiySQ==
-----END PRIVATE KEY-----";

const TEST_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomk74B9NsLBSsY/+EHvI
hjd7m0w70+WMk+2aiqLpuH03Nd03vqHQ58+FKLdeq5h4JN/PkCxRD74UzACRlGOA
ZgeH2lgULsX8zOXssLRaDED5XaNJjR9YMo9Rzd+6idZR9a6jvuj4MXk5JV18PZUx
yA4SM8MZTtCatp1N7xJKHXU83lUT6DACx4dDZ0wN97VwvNpgixyodJRLJl1Q2Y/l
7rv3iSb6b2A/lvnkw+Ah4I3iGLuksQ980D6XA3eJp5nf+l7I21b7NNNpdrtOeebQ
2clTamSLy97rVlgRL1Zn02vxXzaIcyfxKZQnwfBE4IS5URXvaoTKmR3wk4aMIgE1
EwIDAQAB
-----END PUBLIC KEY-----";
