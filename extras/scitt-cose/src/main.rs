use std::env;
use std::fs;
use std::process;

use scitt_cose::validate_scitt_cose_signed_statement;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <cose_file>", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    let tagged_cose_bytes = match fs::read(filename) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error reading file: {}", err);
            process::exit(1);
        }
    };

    match validate_scitt_cose_signed_statement(&tagged_cose_bytes) {
        Ok(_headers) => {
            println!("COSE signature is valid.");
        }
        Err(err) => {
            eprintln!("Error: {}", err);
            process::exit(1);
        }
    };
}
