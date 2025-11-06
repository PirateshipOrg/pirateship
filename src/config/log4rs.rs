// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::env;

use log::LevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config,
};

pub fn default_log4rs_config() -> Config {
    let level = {
        let lvar = env::var("LOG_LEVEL");

        let lvl = match lvar.unwrap_or(String::from("info")).as_str() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "debug" => LevelFilter::Debug,
            "error" => LevelFilter::Error,
            "off" => LevelFilter::Off,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        };

        lvl
    };
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h([{l}][{M}][{d}])} {m}{n}", // [INFO][module][timestamp] message
        )))
        .build();

    Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(level))
        .unwrap()
}
