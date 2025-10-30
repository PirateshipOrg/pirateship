use clap::{Arg, Command};

mod json2proto;
use json2proto::JsonTransaction;
use prost::Message;
use pft::crypto::hash;

fn main() {
    let matches = Command::new("json2digest")
        .about("Utility to get digests from Pirateship transactions in JSON format")
        .version("0.1.0")
        .arg(
            Arg::new("input")
                .help("Path to the JSON transaction file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .help("Path to the output file for the digest")
                .required(true)
                .index(2),
        )
        .get_matches();

    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();

    println!("Loading JSON transaction from: {}", input_path);
    let proto_tx = match JsonTransaction::from_json_file(input_path) {
        Ok(json_tx) => {
            json_tx.to_proto()
        }
        Err(e) => Err(e),
    };

    match proto_tx {
        Ok(proto_tx) => {
            let digest = hash(&proto_tx.encode_to_vec());
            match std::fs::write(output_path, digest) {
                Ok(_) => println!("Digest written to: {}", output_path),
                Err(e) => eprintln!("Failed to write digest: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Failed to load JSON transaction: {}", e);
        }
    };
}