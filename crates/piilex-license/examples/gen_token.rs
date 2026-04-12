/// Generate a production-signed RS256 JWT license token.
///
/// Usage:
///   cargo run --example gen_token -- [email] [tier] [days] [private_key_path]
///
/// Defaults:
///   email: dev@piilex.dev
///   tier:  pro
///   days:  365
///   key:   keys/private.pem (relative to workspace root)
fn main() {
    let email = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dev@piilex.dev".into());
    let tier = std::env::args().nth(2).unwrap_or_else(|| "pro".into());
    let days: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(365);
    let key_path = std::env::args()
        .nth(4)
        .unwrap_or_else(|| "keys/private.pem".into());

    let private_pem = std::fs::read_to_string(&key_path).unwrap_or_else(|e| {
        eprintln!(
            "Error: failed to read private key from '{}': {}",
            key_path, e
        );
        eprintln!("Hint: run from the workspace root, or provide the key path as 4th argument");
        std::process::exit(1);
    });

    let token = piilex_license::generate_token_with_key(&email, &tier, days, &private_pem);
    println!("{}", token);

    eprintln!("Token generated:");
    eprintln!("  Email:   {}", email);
    eprintln!("  Tier:    {}", tier);
    eprintln!("  Expires: {} days", days);
}
