use std::{io::Write, process::Command};

use crate::{
    stealth_error::StealthError,
    types::types::{OperationRequest, ResultType},
    utils::constants::WASM_PATH,
};

pub fn process_with_enarx(
    operation: &OperationRequest,
) -> Result<(Vec<u8>, ResultType), StealthError> {
    let operation_json = serde_json::to_string(&operation).map_err(|e| {
        StealthError::SerializationError(format!("Failed to serialize operation: {}", e))
    })?;

    println!("Serialized Operation: {}", operation_json);

    let mut child = Command::new("enarx")
        .arg("run")
        .arg("--wasmcfgfile")
        .arg("target/Enarx.toml")
        .arg(WASM_PATH)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| StealthError::EnarxError(format!("Failed to spawn Enarx: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(operation_json.as_bytes()).map_err(|e| {
            StealthError::EnarxError(format!("Failed to write to Enarx stdin: {}", e))
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| StealthError::EnarxError(format!("Failed to wait for Enarx: {}", e)))?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(StealthError::EnarxError(format!(
            "Enarx execution failed: {}",
            error
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| StealthError::EnarxError(format!("Failed to parse Enarx output: {}", e)))?;

    println!("Raw stdout from Enarx: {:?}", stdout);

    let result: (Vec<u8>, ResultType) = parse_enarx_output(&stdout)
        .map_err(|e| StealthError::EnarxError(format!("Failed to parse Enarx result: {}", e)))?;

    println!("Result: {:?}", result);

    Ok(result)
}

pub fn parse_enarx_output(output: &str) -> Result<(Vec<u8>, ResultType), StealthError> {
    let json_str = output.lines().last().unwrap_or("");

    println!("JSON string to parse: {}", json_str);
    let result: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        StealthError::DeserializationError(format!("Failed to parse JSON output: {}", e))
    })?;

    let result_bytes = match result["result"].as_array() {
        Some(arr) => arr
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect::<Vec<u8>>(),
        None => {
            return Err(StealthError::InvalidData(
                "Missing result field".to_string(),
            ));
        }
    };

    let result_type = match result["type"].as_str() {
        Some("number") => ResultType::Number,
        Some("string") => ResultType::String,
        Some("binary") => ResultType::Binary,
        _ => return Err(StealthError::InvalidData("Invalid result type".to_string())),
    };

    Ok((result_bytes, result_type))
}
