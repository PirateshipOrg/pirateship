// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.


use std::io::Result;
fn main() -> Result<()> {
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
        &[
            "src/proto/auth.proto",
            "src/proto/consensus.proto",
            "src/proto/client.proto",
            "src/proto/rpc.proto",
            "src/proto/checkpoint.proto",
            "src/proto/execution.proto",
        ],
        &["src/proto"],
    )?;
    Ok(())
}
