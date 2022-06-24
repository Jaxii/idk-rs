fn main() {
  //  println!("cargo:rustc-link-arg-bins=/ALIGN:16");
  //  println!("cargo:rustc-link-arg-bins=/FILEALIGN:1");
    // Merges empty `.rdata` and `.pdata` into .text section saving a few bytes in data
    // directories portion  of PE header.
    /*
        "-C", "link-arg=/MERGE:.edata=.rdata",
    "-C", "link-arg=/MERGE:.rustc=.data",
    "-C", "link-arg=/MERGE:.rdata=.text",
    "-C", "link-arg=/MERGE:.pdata=.text",
     */
    println!("cargo:rustc-link-arg-bins=/MERGE:.edata=.rdata");
    println!("cargo:rustc-link-arg-bins=/MERGE:.rustc=.data");
    println!("cargo:rustc-link-arg-bins=/MERGE:.rdata=.text");
    println!("cargo:rustc-link-arg-bins=/MERGE:.pdata=.text");
    println!("cargo:rustc-link-arg-bins=/MERGE:.pdata=.text");
    // Prevents linking default C runtime libraries.
    println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg-bins=/OPT:REF,ICF");
    //println!("cargo:rustc-link-arg-bins=/INTEGRITYCHECK"); breaks executable :(
    println!("cargo:rustc-link-arg-bins=/ENTRY:main");
    println!("cargo:rustc-link-arg-bins=/EMITPOGOPHASEINFO");
    println!("cargo:rustc-link-arg-bins=/DEBUG:NONE");
    println!("cargo:rustc-link-arg-bins=/NOLOGO");
    println!("cargo:rustc-link-arg-bins=/NXCOMPAT");
    println!("cargo:rustc-link-arg-bins=/DYNAMICBASE");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
    // See: https://github.com/mcountryman/min-sized-rust-windows/pull/7
    println!("cargo:rustc-link-arg-bins=/STUB:stub.exe");

    println!("cargo:rustc-target-feature=-mmx,-sse,+soft-float");
}