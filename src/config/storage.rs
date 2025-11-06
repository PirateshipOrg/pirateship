// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RocksDBConfig {
    pub db_path: String,
    pub write_buffer_size: usize,
    pub max_write_buffer_number: i32,
    pub max_write_buffers_to_merge: i32,
}

impl Default for RocksDBConfig {
    fn default() -> Self {
        Self {
            db_path: String::from("/tmp/testdb"),
            write_buffer_size: 512 * 1024 * 1024,
            max_write_buffer_number: 8,
            max_write_buffers_to_merge: 4,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileStorageConfig {
    pub db_path: String,
    pub memtable_size: usize,
}

impl Default for FileStorageConfig {
    fn default() -> Self {
        Self {
            db_path: String::from("/tmp/testdb"),
            memtable_size: (1 << 10),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum StorageConfig {
    RocksDB(RocksDBConfig),
    FileStorage(FileStorageConfig),
}
