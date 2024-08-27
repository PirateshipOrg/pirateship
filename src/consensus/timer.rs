// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the Apache 2.0 License.

use std::{pin::Pin, sync::{atomic::AtomicBool, Arc}, time::Duration};

use tokio::{sync::{mpsc, Mutex}, task::JoinHandle, time::sleep};

pub struct ResettableTimer {
    pub timeout: Duration,
    tx: mpsc::Sender<bool>,
    rx: Mutex<mpsc::Receiver<bool>>,
    is_cancelled: AtomicBool
}

impl ResettableTimer {
    pub fn new(timeout: Duration) -> Arc<Pin<Box<Self>>> {
        let (tx, rx) = mpsc::channel(1);
        Arc::new(Box::pin(ResettableTimer {
            timeout, tx, rx: Mutex::new(rx),
            is_cancelled: AtomicBool::new(false)
        }))
    }

    pub async fn fire_now(self: &Arc<Pin<Box<Self>>>) {
        let tx = self.tx.clone();
        let _ = tx.try_send(true);
    }

    pub async fn run(self: &Arc<Pin<Box<Self>>>) -> JoinHandle<()>{
        let tx = self.tx.clone();
        let tout = self.timeout;
        let _self = self.clone();
        tokio::spawn(async move {
            loop {
                // This sleep has ms accuracy.
                sleep(tout).await;

                // Logic: Send the timeout signal, only if the is_cancelled is false.
                // If is_cancelled, reset it to false and skip sending this signal.
                // Sleeps a little extra: Cannot guarantee very accurate resets.
                // |-----(Timeout 1)-----|-----(Timeout 2)-----|
                //       ^                     ^               ^
                //       |                     |               |
                //       Reset                 |               |
                //                      Should have fired here |
                //                                    Fires here

                match _self.is_cancelled.compare_exchange(
                    true,     // If it is currenty true
                    false,        // Set it to false
                    std::sync::atomic::Ordering::Release,    
                    std::sync::atomic::Ordering::Relaxed)
                {
                    Ok(_) => {
                        // Setting was successful.
                        // Do nothing. Skip this tick.
                    },
                    Err(_) => {
                        let _ = tx.send(true).await;
                    }
                };
                
            }
        })
    }

    pub async fn wait(self: &Arc<Pin<Box<Self>>>) -> bool {
        let mut rx = self.rx.lock().await;
        rx.recv().await;
        true
    }

    pub fn reset(self: &Pin<Box<Self>>) {
        let _ = self.is_cancelled.compare_exchange(
            false,     // If it is currenty false
            true,        // Set it to true
            std::sync::atomic::Ordering::Acquire,    
            std::sync::atomic::Ordering::Relaxed);
    }
}