mod atomic_struct;
pub use atomic_struct::*;

mod agnostic_ref;
pub use agnostic_ref::*;

mod storage;
pub use storage::*;

mod file_storage;
pub use file_storage::*;

mod storage_service;
pub use storage_service::*;

mod serialize;
pub use serialize::*;

mod perf;
pub use perf::*;

pub mod timer;


pub mod channel {
    mod channel_tokio {
        pub type Sender<T> = tokio::sync::mpsc::Sender<T>;
        pub type Receiver<T> = tokio::sync::mpsc::Receiver<T>;
    
        pub fn make_channel<T>(buffer: usize) -> (Sender<T>, Receiver<T>) {
            tokio::sync::mpsc::channel(buffer)
        }
    }

    mod channel_async {
        #[cfg(feature = "perf")]
        use std::{sync::{atomic::AtomicUsize, Arc}, time::Instant};

        #[cfg(not(feature = "perf"))]
        pub struct AsyncSenderWrapper<T>(async_channel::Sender<T>);
        #[cfg(feature = "perf")]
        pub struct AsyncSenderWrapper<T>(async_channel::Sender<(Instant, T)>);

        impl<T> Clone for AsyncSenderWrapper<T> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        #[cfg(not(feature = "perf"))]
        #[derive(Clone)]
        pub struct AsyncReceiverWrapper<T>(async_channel::Receiver<T>);


        #[cfg(feature = "perf")]
        #[derive(Clone)]
        pub struct AsyncReceiverWrapper<T>(async_channel::Receiver<(Instant, T)>, Arc<AtomicUsize>);
        
        impl<T> AsyncReceiverWrapper<T> {
            pub async fn recv(&self) -> Option<T> {
                match self.0.recv().await {
                    #[cfg(not(feature = "perf"))]
                    Ok(e) => Some(e),
                    #[cfg(feature = "perf")]
                    Ok((start, e)) => {
                        let num = self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if num % 10000 == 0 {
                            let elapsed = start.elapsed();
                            if elapsed.as_micros() > 0 {
                                println!("Queue wait time: {} us", elapsed.as_micros());
                            }
                        }

                        Some(e)
                    }
                    Err(_) => None,
                }
            }

            #[cfg(feature = "channel_monitoring")]
            pub fn len(&self) -> usize {
                self.0.len()
            }
        }


        impl <T> AsyncSenderWrapper<T> {

            #[cfg(not(feature = "perf"))]
            pub async fn send(&self, e: T) -> Result<(), async_channel::SendError<T>> {
                self.0.send(e).await

            }

            #[cfg(feature = "perf")]
            pub async fn send(&self, e: T) -> Result<(), async_channel::SendError<(Instant, T)>> {
                self.0.send((Instant::now(), e)).await
            }

            #[cfg(feature = "channel_monitoring")]
            pub fn len(&self) -> usize {
                self.0.len()
            }
        }


        pub type Sender<T> = AsyncSenderWrapper<T>;
        pub type Receiver<T> = AsyncReceiverWrapper<T>;
    
        pub fn make_channel<T>(buffer: usize) -> (Sender<T>, Receiver<T>) {
            let (tx, rx) = async_channel::bounded(buffer);

            #[cfg(feature = "perf")]
            return (AsyncSenderWrapper(tx), AsyncReceiverWrapper(rx, Arc::new(AtomicUsize::new(0))));

            #[cfg(not(feature = "perf"))]
            (AsyncSenderWrapper(tx), AsyncReceiverWrapper(rx))
        }
    }


    /// Kanal doesn't seem to have ordered delivery sometimes.
    mod channel_kanal {
        pub struct AsyncReceiverWrapper<T>(kanal::AsyncReceiver<T>);
        impl<T> AsyncReceiverWrapper<T> {
            pub async fn recv(&mut self) -> Option<T> {
                match self.0.recv().await {
                    Ok(e) => Some(e),
                    Err(_) => None,
                }
            }
        }
        pub type Sender<T> = kanal::AsyncSender<T>;
        pub type Receiver<T> = AsyncReceiverWrapper<T>;
    
        pub fn make_channel<T>(buffer: usize) -> (Sender<T>, Receiver<T>) {
            let (tx, rx) = kanal::bounded_async(buffer);
            (tx, AsyncReceiverWrapper(rx))
        }
    }

    pub use channel_async::*;

}
