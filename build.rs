fn main() {
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
