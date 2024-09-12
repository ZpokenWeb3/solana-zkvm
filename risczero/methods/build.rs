use risc0_build::embed_methods;
use risc0_build_ethereum::generate_solidity_files;

// Paths where the generated Solidity files will be written.
const SOLIDITY_IMAGE_ID_PATH: &str = "../contracts/src/ImageID.sol";
const SOLIDITY_ELF_PATH: &str = "../contracts/tests/Elf.sol";

fn main() {
    // Generate Rust source files for the methods crate.
    let guests = embed_methods();

    // Generate Solidity source files for use with Forge.
    let solidity_opts = risc0_build_ethereum::Options::default()
        .with_image_id_sol_path(SOLIDITY_IMAGE_ID_PATH)
        .with_elf_sol_path(SOLIDITY_ELF_PATH);

    generate_solidity_files(guests.as_slice(), &solidity_opts).unwrap();
}
