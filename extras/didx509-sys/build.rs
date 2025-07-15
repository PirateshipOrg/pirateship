use std::env;

fn main() {
    // Use pkg-config to find OpenSSL
    let openssl = pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("openssl")
        .unwrap();

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=didx509_wrapper.cpp");
    println!("cargo:rerun-if-changed=didx509cpp/didx509cpp.h");

    // Add OpenSSL library search paths first
    for lib_path in &openssl.link_paths {
        println!("cargo:rustc-link-search=native={}", lib_path.display());
    }

    // Also add the standard library paths
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/lib");

    // Compile the C++ wrapper
    let mut builder = cc::Build::new();
    builder
        .cpp(true)
        .file("didx509_wrapper.cpp")
        .include(".") // Include current directory for wrapper.h
        .include("didx509cpp") // Include submodule directory for didx509cpp.h
        .flag("-std=c++17") // Use C++17 standard
        .flag("-O2"); // Optimize

    // Add OpenSSL include paths
    for include_path in &openssl.include_paths {
        builder.include(include_path);
    }

    // Add debug symbols in debug mode
    if env::var("PROFILE").unwrap() == "debug" {
        builder.flag("-g");
    }

    builder.compile("didx509_wrapper");

    // Link libraries in proper order
    println!("cargo:rustc-link-lib=static=didx509_wrapper");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=stdc++");
}
