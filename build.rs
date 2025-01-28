use std::env;
use std::path::PathBuf;

fn main() {
    // 1) Tell Cargo where to find the library at link time
    println!("cargo:rustc-link-search=native=/home/ubuntu/EUSignCP-Linux-20250102/Modules");
    
    // 2) Tell Cargo which library to link (normally searches for `libeuscp.so`)
    //    If your file is literally named `euscp.so`, rename it to `libeuscp.so`
    //    for standard -l linking.  Or see notes below.
    println!("cargo:rustc-link-lib=dylib=euscp");

    // 3) Configure bindgen
    let builder = bindgen::Builder::default()
        // The header that declares EULoad, EUUnload, EUGetInterface, etc.
        .header("bindgen_interface/header.h")
        
        // Ensures Cargo automatically rebuilds if the header changes
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .blocklist_item("EULoad")
        .blocklist_item("EUGetInterface")
        .blocklist_item("EUUnload")
        ;

    let bindings = builder
        .generate()
        .expect("Unable to generate bindings with bindgen");

    // 4) Write them to $OUT_DIR/bindings.rs
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
