use std::io::{self, Read};

use stealth_engine::types::types::{OperationRequest, ResultType};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let mut operation_request: OperationRequest = match serde_json::from_str(&input) {
        Ok(op) => op,
        Err(_) => {
            eprintln!("Invalid input JSON");
            std::process::exit(1);
        }
    };

    println!("Operation Request: {:?}", operation_request);

    let result = match operation_request.process_encrypted_data() {
        Ok(res) => res,
        Err(_) => {
            eprintln!("Failed to process encrypted data");
            std::process::exit(1);
        }
    };

    let output = serde_json::json!({
        "result": result.0,
        "type": match result.1 {
            ResultType::Number => "number",
            ResultType::String => "string",
            ResultType::Binary => "binary",
        }
    });

    

    println!("{}", serde_json::to_string(&output).unwrap());
}
