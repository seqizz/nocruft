use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

// Build the BPF C source into a CO-RE object and generate a Rust skeleton.
// The skeleton is included via `include!` in src/tracer.rs (or src/main.rs for MVP-1).
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf_src = manifest_dir
        .parent()
        .unwrap() // crates/
        .join("nocruft-bpf")
        .join("src")
        .join("nocruft.bpf.c");

    let vmlinux_dir = manifest_dir
        .parent()
        .unwrap()
        .join("nocruft-bpf")
        .join("src");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let skel_out = out_dir.join("nocruft.skel.rs");

    SkeletonBuilder::new()
        .source(&bpf_src)
        // -I points clang at vmlinux.h
        .clang_args(["-I", vmlinux_dir.to_str().unwrap(), "-Wno-unused-function"])
        .build_and_generate(&skel_out)
        .expect("failed to build BPF skeleton");

    println!("cargo:rerun-if-changed={}", bpf_src.display());
    println!(
        "cargo:rerun-if-changed={}",
        vmlinux_dir.join("vmlinux.h").display()
    );
}
