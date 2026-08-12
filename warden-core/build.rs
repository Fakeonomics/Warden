fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WARDEN_LCKEY");
    let key = std::env::var("WARDEN_LCKEY")
        .unwrap_or_else(|_| format!("obs-core-{}-salt", env!("CARGO_PKG_VERSION")));
    println!("cargo:rustc-env=LITCRYPT_ENCKEY={}", key);
}
