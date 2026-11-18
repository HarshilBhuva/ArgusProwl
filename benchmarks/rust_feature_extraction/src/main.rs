use std::collections::{HashMap, HashSet};
use std::env;
use std::hint::black_box;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Event {
    seq: u64,
    dst_port: u16,
    dst_ip: u16,
    src_port: u16,
    state: &'static str,
    history: &'static str,
    duration: f64,
    orig_bytes: u64,
    resp_bytes: u64,
}

fn make_event(seq: u64) -> Event {
    Event {
        seq,
        dst_port: [80, 443, 22, 8080][(seq % 4) as usize],
        dst_ip: (seq % 250 + 1) as u16,
        src_port: (40000 + seq % 20000) as u16,
        state: ["SF", "REJ", "S0", "OTH"][(seq % 4) as usize],
        history: if seq % 3 == 0 { "S" } else { "ShADadfF" },
        duration: (seq % 500) as f64 / 100.0,
        orig_bytes: seq % 4096,
        resp_bytes: seq % 8192,
    }
}

fn run_worker(events: usize) -> (usize, f64, f64) {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(events);
    let mut checksum = 0.0_f64;
    for i in 0..events {
        let event = make_event(i as u64);
        let call_start = Instant::now();

        // Aggregate the same per-source window as the Python component benchmark.
        let mut dst_ports = HashSet::new();
        let mut dst_ips = HashSet::new();
        let mut src_ports = HashSet::new();
        let mut port_counts: HashMap<u16, usize> = HashMap::new();
        let mut failed = 0_u64;
        let mut syn = 0_u64;
        let mut duration_count = 0_u64;
        let mut duration_sum = 0.0;
        let mut mean = 0.0;
        let mut m2 = 0.0;
        let mut min_duration = 0.0_f64;
        let mut max_duration = 0.0_f64;
        let mut sent = 0_u64;
        let mut received = 0_u64;

        // The production extractor recomputes features from the active window.
        // Reproduce that O(window) aggregation rather than benchmarking a
        // fundamentally different incremental algorithm.
        for j in 0..=i {
            let e = make_event(j as u64);
            if e.dst_port > 0 {
                dst_ports.insert(e.dst_port);
                *port_counts.entry(e.dst_port).or_insert(0) += 1;
            }
            dst_ips.insert(e.dst_ip);
            if e.src_port > 0 { src_ports.insert(e.src_port); }
            if matches!(e.state, "REJ" | "S0" | "OTH") { failed += 1; }
            if e.history.contains('S') { syn += 1; }
            if e.duration > 0.0 {
                duration_count += 1;
                duration_sum += e.duration;
                let delta = e.duration - mean;
                mean += delta / duration_count as f64;
                m2 += delta * (e.duration - mean);
                if duration_count == 1 { min_duration = e.duration; max_duration = e.duration; }
                else { min_duration = min_duration.min(e.duration); max_duration = max_duration.max(e.duration); }
            }
            if e.orig_bytes > 0 { sent += e.orig_bytes; }
            if e.resp_bytes > 0 { received += e.resp_bytes; }
        }
        let avg = if duration_count > 0 { duration_sum / duration_count as f64 } else { 0.0 };
        let stddev = if duration_count < 2 { 0.0 } else { (m2 / duration_count as f64).sqrt() };
        let concentration = port_counts.values().copied().max().unwrap_or(0) as f64 / (i + 1) as f64;
        let span = event.seq as f64 / 1_000_000.0;
        let rate = if span > 0.0 { (i + 1) as f64 / span } else { 0.0 };
        checksum += dst_ports.len() as f64 + dst_ips.len() as f64 + src_ports.len() as f64
            + failed as f64 + syn as f64 + avg + stddev + min_duration + max_duration
            + sent as f64 + received as f64 + concentration + rate;
        latencies.push(call_start.elapsed().as_nanos() as f64);
    }
    let elapsed = started.elapsed().as_secs_f64();
    let checksum = black_box(checksum);
    (events, elapsed, checksum)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let events: usize = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(1500);
    let workers: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1);
    if events == 0 || workers == 0 { eprintln!("events and workers must be positive"); std::process::exit(2); }

    let started = Instant::now();
    let results = thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..workers { handles.push(scope.spawn(|| run_worker(events))); }
        handles.into_iter().map(|h| h.join().expect("worker panicked")).collect::<Vec<_>>()
    });
    let elapsed = started.elapsed().as_secs_f64();
    let processed: usize = results.iter().map(|r| r.0).sum();
    let checksum: f64 = results.iter().map(|r| r.2).sum();
    println!("{{\"language\":\"rust\",\"workers\":{},\"offered_events\":{},\"processed_events\":{},\"unprocessed_events\":{},\"wall_seconds\":{:.6},\"throughput_events_per_second\":{:.2},\"checksum\":{:.9}}}",
        workers, events * workers, processed, events * workers - processed, elapsed,
        processed as f64 / elapsed, checksum);
}
