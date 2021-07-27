use std::path::PathBuf;

// Necessary because of this issue: https://github.com/rust-lang/cargo/issues/9641
fn main() -> anyhow::Result<()> {
    let mcu = std::env::var("DEP_ESP_IDF_MCU").map_err(|s| anyhow::anyhow!(s))?;

    if mcu == "esp32s2" {
        // Future; might be possible once https://github.com/rust-lang/cargo/issues/9096 hits Cargo nightly:
        //let ulp_elf = PathBuf::from(env::var_os("CARGO_BIN_FILE_RUST_ESP32_ULP_HELLO_rust_esp32_ulp_hello").unwrap());

        let ulp_elf = PathBuf::from("ulp").join("rust-esp32-ulp-hello");
        pio::symgen::run(&ulp_elf, 0x50_000_000)?; // This is where the RTC Slow Mem is mapped within the ESP32-S2 memory space
        pio::bingen::run(&ulp_elf)?;

        pio::cargo::build::track(ulp_elf)?;
    }

    println!("cargo:rustc-cfg={}", mcu);
    pio::cargo::build::LinkArgs::output_propagated("ESP_IDF")
}