// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

fn main() {
    println!("cargo:rerun-if-changed=linker-aarch64.ld");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none")
    {
        for arg in [
            "--pie",
            "-Bsymbolic",
            "--no-dynamic-linker",
            "-z",
            "notext",
            "--apply-dynamic-relocs",
        ] {
            println!("cargo:rustc-link-arg-bin=kernal-core-aarch64={arg}");
        }
    }
}
