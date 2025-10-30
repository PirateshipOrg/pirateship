// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::{ops::Deref, pin::Pin, sync::Arc};

pub mod auth;
pub mod client;
pub mod server;

/// Do not run these tests all together.
/// The tests needs a config directory.
/// Create it by running: sh scripts/gen_local_config.sh configs 7 scripts/local_template.json
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SenderType {
    Anon,
    Auth(String, u64 /* client_sub_id */),
}

impl SenderType {
    pub fn to_name_and_sub_id(&self) -> (String, u64) {
        match self {
            SenderType::Anon => (String::from("Anon"), 0),
            SenderType::Auth(s, id) => (s.to_owned(), *id),
        }
    }
}

impl SenderType {
    fn to_string(&self) -> String {
        match self {
            SenderType::Anon => String::from("Anon"),
            SenderType::Auth(s, id) => s.to_owned() + "#" + &id.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct Message(Arc<Vec<u8>>, usize, SenderType);

#[derive(Clone)]
pub struct MessageRef<'a>(pub &'a Vec<u8>, pub usize, pub &'a SenderType);

#[derive(Clone)]
pub struct PinnedMessage(Arc<Pin<Box<(Vec<u8>, usize, SenderType)>>>);

impl Message {
    pub fn from(arr: Vec<u8>, sz: usize, sender: SenderType) -> Message {
        Message(Arc::new(arr), sz, sender)
    }

    pub fn as_ref<'a>(&'a self) -> MessageRef<'a> {
        MessageRef(self.0.as_ref(), self.1, &self.2)
    }
}

impl<'a> MessageRef<'a> {
    pub fn from(arr: &'a Vec<u8>, sz: usize, sender: &'a SenderType) -> MessageRef<'a> {
        MessageRef(arr, sz, sender)
    }
}

impl Deref for Message {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> MessageRef<'a> {
    pub fn size(&self) -> usize {
        self.1
    }

    pub fn sender(&self) -> &SenderType {
        &self.2
    }
}

impl<'a> Deref for MessageRef<'a> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PinnedMessage {
    pub fn from(arr: Vec<u8>, sz: usize, sender: SenderType) -> PinnedMessage {
        PinnedMessage(Arc::new(Box::pin((arr, sz, sender))))
    }

    pub fn as_ref<'a>(&'a self) -> MessageRef<'a> {
        MessageRef(self.0 .0.as_ref(), self.0 .1, &self.0 .2)
    }
}

pub mod proto {
    pub mod auth {
        include!(concat!(env!("OUT_DIR"), "/proto.auth.rs"));
    }
}
