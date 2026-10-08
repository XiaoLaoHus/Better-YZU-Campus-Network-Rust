fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").expect("Missing package version");
    let display_version = version.replace("+lite", "Lite");
    println!("cargo:rustc-env=APP_VERSION={display_version}");
    println!("cargo:rerun-if-changed=assets/campus-link.ico");
    println!("cargo:rerun-if-changed=assets/windows.manifest");
    #[cfg(windows)]
    {
        winres::WindowsResource::new()
            .set_icon("assets/campus-link.ico")
            .set_manifest_file("assets/windows.manifest")
            .set("FileDescription", "扬大校园网 · Campus Link")
            .set("ProductName", "Better YZU Campus Network")
            .compile()
            .expect("Unable to embed Windows icon and manifest");
    }
}
