use risc0_build::embed_methods;
use risc0_build_ethereum::generate_solidity_files;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;


// Paths where the generated Solidity files will be written.
const SOLIDITY_IMAGE_ID_PATH: &str = "../contracts/src/ImageID.sol";
const SOLIDITY_ELF_PATH: &str = "../contracts/tests/Elf.sol";
const ENV_IMAGE_ID_PATH: &str = "../contracts/.env";

fn update_or_create_env(image_id: &str, env_path: &str) -> io::Result<()> {
    if !Path::new(env_path).exists() {
        OpenOptions::new().create(true).write(true).open(env_path)?;
    }

    let file_content = fs::read_to_string(env_path)?;
    let mut lines: Vec<String> = file_content.lines().map(|line| line.to_string()).collect();
    let mut image_id_found = false;

    for line in lines.iter_mut() {
        if line.starts_with("IMAGE_ID=") {
            *line = format!("IMAGE_ID={}", image_id);
            image_id_found = true;
            break;
        }
    }

    if !image_id_found {
        lines.push(format!("IMAGE_ID={}", image_id));
    }

    let mut file = OpenOptions::new().write(true).truncate(true).open(env_path)?;
    writeln!(file, "{}", lines.join("\n"))?;

    Ok(())
}

fn extract_image_id_from_solidity(path: &str) -> Result<String, &'static str> {
    let content = fs::read_to_string(path).unwrap();

    let start_marker = "bytes32(0x";
    let end_marker = ")";

    if let Some(start_pos) = content.find(start_marker) {
        let start_pos = start_pos + start_marker.len();
        if let Some(end_pos) = content[start_pos..].find(end_marker) {
            let end_pos = start_pos + end_pos;
            let hex_string = &content[start_pos..end_pos];
            return Ok(format!("0x{}", hex_string.trim()));
        }
    }
    Err("Hex string not found")
}


fn main() {
    // Generate Rust source files for the methods crate.
    let guests = embed_methods();

    // Generate Solidity source files for use with Forge.
    let solidity_opts = risc0_build_ethereum::Options::default()
        .with_image_id_sol_path(SOLIDITY_IMAGE_ID_PATH)
        .with_elf_sol_path(SOLIDITY_ELF_PATH);

    generate_solidity_files(guests.as_slice(), &solidity_opts).unwrap();

    // Write to .env for use with Hardhat
    let image_id = extract_image_id_from_solidity(SOLIDITY_IMAGE_ID_PATH).unwrap();
    update_or_create_env(&image_id, ENV_IMAGE_ID_PATH).unwrap();
}
