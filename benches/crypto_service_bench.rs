// use std::time::{Duration, Instant};

// use pft::crypto::{AtomicKeyStore, CryptoService, CryptoServiceConnector, KeyStore};
// use tokio::task::JoinSet;

// async fn hash_worker(mut crypto: CryptoServiceConnector, payload_size: usize, iter_num: usize) -> Vec<Duration> {
//     let payload = vec![2u8; payload_size];

//     let mut latencies = Vec::with_capacity(iter_num);
//     for _ in 0..iter_num {
//         let now = Instant::now();
//         crypto.hash(&payload).await;
//         latencies.push(now.elapsed());
//     }

//     latencies
// }

// async fn sign_worker(mut crypto: CryptoServiceConnector, payload_size: usize, iter_num: usize) -> Vec<Duration> {
//     let payload = vec![2u8; payload_size];

//     let mut latencies = Vec::with_capacity(iter_num);
//     for _ in 0..iter_num {
//         let now = Instant::now();
//         crypto.sign(&payload).await;
//         latencies.push(now.elapsed());
//     }

//     latencies
// }

// async fn verify_worker(mut crypto: CryptoServiceConnector, payload_size: usize, iter_num: usize) -> Vec<Duration> {
//     let payload = vec![2u8; payload_size];

//     let mut latencies = Vec::with_capacity(iter_num);
//     let sig = crypto.sign(&payload).await;
//     for _ in 0..iter_num {
//         let now = Instant::now();
//         crypto.verify(&payload, &String::from("node1"), &sig).await;
//         latencies.push(now.elapsed());
//     }

//     latencies
// }

// async fn verify_fail_worker(mut crypto: CryptoServiceConnector, payload_size: usize, iter_num: usize) -> Vec<Duration> {
//     let payload = vec![2u8; payload_size];

//     let mut latencies = Vec::with_capacity(iter_num);
//     let mut sig = crypto.sign(&payload).await;
//     sig[0] = !sig[0];

//     for _ in 0..iter_num {
//         let now = Instant::now();
//         crypto.verify(&payload, &String::from("node1"), &sig).await;
//         latencies.push(now.elapsed());
//     }

//     latencies
// }

// async fn run_bench_with_n_tasks(num_tasks: usize) {
//     let key_store = KeyStore::new(
//         &String::from("configs/signing_pub_keys.keylist"),
//         &String::from("configs/node1_signing_privkey.pem"),
//     );

//     let mut crypto_service = CryptoService::new(num_tasks, AtomicKeyStore::new(key_store));
//     crypto_service.run();

//     const ITER_NUM: usize = 1_000;
//     const WORKER_NUM: usize = 8;
//     const PAYLOAD_SIZES: [usize; 5] = [32, 1024, 4096, 8192, 512000];

//     for payload_size in PAYLOAD_SIZES {
//         let mut handles = JoinSet::new();
    
//         let start = Instant::now();
//         for _ in 0..WORKER_NUM {
//             let crypto = crypto_service.get_connector();
//             handles.spawn(async move {
//                 hash_worker(crypto, payload_size, ITER_NUM).await
//             });
//         }

//         let results = handles.join_all().await;
//         let total_time = start.elapsed();

//         let tput = ((WORKER_NUM * ITER_NUM) as f64) / total_time.as_secs_f64();
//         let mut latencies = results.iter().fold(Vec::<Duration>::new(), |acc, x| {
//             let mut y = acc.clone();
//             y.extend(x);
//             y
//         });

//         latencies.sort();
//         let min_latency = latencies.first().unwrap().as_nanos();
//         let max_latency = latencies.last().unwrap().as_nanos();
//         let avg_latency = (latencies.iter().fold(0u128, |acc, x| { acc + x.as_nanos() }) as f64) / (latencies.len() as f64); 


//         println!("Workers: {} Payload size: {} Hash Throughput: {} req/s Latency min: {} max: {} mean: {} ns", num_tasks, payload_size, tput, min_latency, max_latency, avg_latency);
//     }

//     for payload_size in PAYLOAD_SIZES {
//         let mut handles = JoinSet::new();
    
//         let start = Instant::now();
//         for _ in 0..WORKER_NUM {
//             let crypto = crypto_service.get_connector();
//             handles.spawn(async move {
//                 sign_worker(crypto, payload_size, ITER_NUM).await
//             });
//         }

//         let results = handles.join_all().await;
//         let total_time = start.elapsed();

//         let tput = ((WORKER_NUM * ITER_NUM) as f64) / total_time.as_secs_f64();
//         let mut latencies = results.iter().fold(Vec::<Duration>::new(), |acc, x| {
//             let mut y = acc.clone();
//             y.extend(x);
//             y
//         });

//         latencies.sort();
//         let min_latency = latencies.first().unwrap().as_nanos();
//         let max_latency = latencies.last().unwrap().as_nanos();
//         let avg_latency = (latencies.iter().fold(0u128, |acc, x| { acc + x.as_nanos() }) as f64) / (latencies.len() as f64); 


//         println!("Workers: {} Payload size: {} Sign Throughput: {} req/s Latency min: {} max: {} mean: {} ns", num_tasks, payload_size, tput, min_latency, max_latency, avg_latency);
//     }

//     for payload_size in PAYLOAD_SIZES {
//         let mut handles = JoinSet::new();
    
//         let start = Instant::now();
//         for _ in 0..WORKER_NUM {
//             let crypto = crypto_service.get_connector();
//             handles.spawn(async move {
//                 verify_worker(crypto, payload_size, ITER_NUM).await
//             });
//         }

//         let results = handles.join_all().await;
//         let total_time = start.elapsed();

//         let tput = ((WORKER_NUM * ITER_NUM) as f64) / total_time.as_secs_f64();
//         let mut latencies = results.iter().fold(Vec::<Duration>::new(), |acc, x| {
//             let mut y = acc.clone();
//             y.extend(x);
//             y
//         });

//         latencies.sort();
//         let min_latency = latencies.first().unwrap().as_nanos();
//         let max_latency = latencies.last().unwrap().as_nanos();
//         let avg_latency = (latencies.iter().fold(0u128, |acc, x| { acc + x.as_nanos() }) as f64) / (latencies.len() as f64); 


//         println!("Workers: {} Payload size: {} Verify Throughput: {} req/s Latency min: {} max: {} mean: {} ns", num_tasks, payload_size, tput, min_latency, max_latency, avg_latency);
//     }

//     for payload_size in PAYLOAD_SIZES {
//         let mut handles = JoinSet::new();
    
//         let start = Instant::now();
//         for _ in 0..WORKER_NUM {
//             let crypto = crypto_service.get_connector();
//             handles.spawn(async move {
//                 verify_fail_worker(crypto, payload_size, ITER_NUM).await
//             });
//         }

//         let results = handles.join_all().await;
//         let total_time = start.elapsed();

//         let tput = ((WORKER_NUM * ITER_NUM) as f64) / total_time.as_secs_f64();
//         let mut latencies = results.iter().fold(Vec::<Duration>::new(), |acc, x| {
//             let mut y = acc.clone();
//             y.extend(x);
//             y
//         });

//         latencies.sort();
//         let min_latency = latencies.first().unwrap().as_nanos();
//         let max_latency = latencies.last().unwrap().as_nanos();
//         let avg_latency = (latencies.iter().fold(0u128, |acc, x| { acc + x.as_nanos() }) as f64) / (latencies.len() as f64); 


//         println!("Workers: {} Payload size: {} Verify_Fail Throughput: {} req/s Latency min: {} max: {} mean: {} ns", num_tasks, payload_size, tput, min_latency, max_latency, avg_latency);
//     }

//     crypto_service.get_connector().kill().await;


// }

// #[tokio::main]
// async fn main() {
//     const NUM_TASKS: [usize; 4] = [1, 2, 4, 8];
//     for num_tasks in NUM_TASKS {
//         run_bench_with_n_tasks(num_tasks).await;
//     }
// }