use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::hint::black_box;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use uuid::Uuid;

const WINDOW_SECONDS: i64 = 60;
const MAX_EVENTS_PER_WINDOW: usize = 512;
const MAX_ACTIVE_WINDOWS: usize = 16;
const SOURCE_COUNT: usize = 8;

#[derive(Clone)]
struct NormalizedEvent {
    event_id: Uuid,
    source_type: String,
    event_type: String,
    timestamp: DateTime<Utc>,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    protocol: String,
    hostname: String,
    sensor: String,
    username: String,
    process_name: String,
    pid: u32,
    command_line: String,
    severity: String,
    raw_event: Option<Value>,
    metadata: HashMap<String, Value>,
    tags: Vec<String>,
    schema_version: u32,
    source_record_id: Option<String>,
    attributes: HashMap<String, Value>,
}

impl NormalizedEvent {
    fn new(sequence: usize, base: DateTime<Utc>) -> Result<Self, String> {
        let source_index = sequence % SOURCE_COUNT;
        let src_ip = format!("192.0.2.{}", source_index + 1);
        let dst_ip = format!("198.51.100.{}", sequence % 250 + 1);
        let src_port = 40000 + (sequence % 20000) as u16;
        let dst_port = [80, 443, 22, 8080][sequence % 4];
        let mut attributes = HashMap::with_capacity(5);
        attributes.insert("conn_state".into(), json!(["SF", "REJ", "S0", "OTH"][sequence % 4]));
        attributes.insert("history".into(), json!(if sequence % 3 == 0 { "S" } else { "ShADadfF" }));
        attributes.insert("duration".into(), json!((sequence % 500) as f64 / 100.0));
        attributes.insert("orig_bytes".into(), json!(sequence % 4096));
        attributes.insert("resp_bytes".into(), json!(sequence % 8192));
        let event = Self {
            event_id: Uuid::new_v4(),
            source_type: "benchmark".into(),
            event_type: "network_connection".into(),
            timestamp: base + Duration::milliseconds((sequence * 10) as i64),
            src_ip, src_port, dst_ip, dst_port,
            protocol: "tcp".into(),
            hostname: format!("sensor-{}", source_index % 4),
            sensor: format!("sensor-{}", source_index % 4),
            username: format!("user-{}", sequence % 16),
            process_name: "benchmark-client".into(),
            pid: 1000 + (sequence % 1000) as u32,
            command_line: "benchmark-client --connect".into(),
            severity: "INFO".into(),
            raw_event: None,
            metadata: HashMap::new(),
            tags: Vec::new(),
            schema_version: 1,
            source_record_id: None,
            attributes,
        };
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<(), String> {
        if self.source_type.trim().is_empty() || self.event_type.trim().is_empty() || self.schema_version < 1 {
            return Err("source_type/event_type must not be empty".into());
        }
        IpAddr::from_str(&self.src_ip).map_err(|_| "invalid src_ip")?;
        IpAddr::from_str(&self.dst_ip).map_err(|_| "invalid dst_ip")?;
        Ok(())
    }

    fn text(&self, key: &str) -> &str {
        self.attributes.get(key).and_then(Value::as_str).unwrap_or("")
    }
    fn number(&self, key: &str) -> f64 {
        self.attributes.get(key).and_then(Value::as_f64).unwrap_or(0.0)
    }
    fn integer(&self, key: &str) -> u64 {
        self.attributes.get(key).and_then(Value::as_u64).unwrap_or(0)
    }
}

struct SlidingWindow {
    events: VecDeque<Arc<NormalizedEvent>>,
    watermark: Option<DateTime<Utc>>,
}
impl SlidingWindow {
    fn new() -> Self { Self { events: VecDeque::new(), watermark: None } }
    fn add(&mut self, event: Arc<NormalizedEvent>) {
        let watermark = self.watermark.map_or(event.timestamp, |old| old.max(event.timestamp));
        self.watermark = Some(watermark);
        self.evict(watermark);
        if event.timestamp < watermark - Duration::seconds(WINDOW_SECONDS) { return; }
        self.events.push_back(event);
        while self.events.len() > MAX_EVENTS_PER_WINDOW { self.events.pop_front(); }
    }
    fn evict(&mut self, reference: DateTime<Utc>) {
        let cutoff = reference - Duration::seconds(WINDOW_SECONDS);
        while self.events.front().is_some_and(|event| event.timestamp < cutoff) {
            self.events.pop_front();
        }
    }
    fn snapshot(&mut self, reference: DateTime<Utc>) -> Vec<Arc<NormalizedEvent>> {
        self.evict(self.watermark.map_or(reference, |mark| mark.max(reference)));
        self.events.iter().cloned().collect()
    }
}

struct FeatureVector {
    vector_id: Uuid,
    event_id: Uuid,
    created_at: DateTime<Utc>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: String,
    values: [f64; 20],
    extra: HashMap<String, Value>,
}
impl FeatureVector {
    fn validate(&self) -> Result<(), String> {
        if self.window_start >= self.window_end { return Err("invalid vector window".into()); }
        if !(0.0..=1.0).contains(&self.values[14]) { return Err("invalid port concentration".into()); }
        Ok(())
    }
}

fn aggregate(events: &[Arc<NormalizedEvent>]) -> Result<FeatureVector, String> {
    let last = events.last().ok_or("empty window")?;
    let first = events.first().unwrap();
    let mut ports = HashSet::new();
    let mut ips = HashSet::new();
    let mut src_ports = HashSet::new();
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let (mut failed, mut syn, mut duration_count, mut sent, mut received) = (0_u64, 0_u64, 0_u64, 0_u64, 0_u64);
    let (mut duration_sum, mut mean, mut m2, mut min_duration, mut max_duration) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for event in events {
        if event.dst_port > 0 { ports.insert(event.dst_port); *port_counts.entry(event.dst_port).or_insert(0) += 1; }
        if !event.dst_ip.is_empty() { ips.insert(event.dst_ip.as_str()); }
        if event.src_port > 0 { src_ports.insert(event.src_port); }
        if ["REJ", "S0", "OTH"].contains(&event.text("conn_state")) { failed += 1; }
        if event.text("history").contains('S') { syn += 1; }
        let duration = event.number("duration");
        if duration > 0.0 {
            duration_count += 1;
            duration_sum += duration;
            let delta = duration - mean;
            mean += delta / duration_count as f64;
            m2 += delta * (duration - mean);
            if duration_count == 1 { min_duration = duration; max_duration = duration; }
            else { min_duration = min_duration.min(duration); max_duration = max_duration.max(duration); }
        }
        let orig = event.integer("orig_bytes");
        let resp = event.integer("resp_bytes");
        if orig > 0 { sent += orig; }
        if resp > 0 { received += resp; }
    }
    let span = (last.timestamp - first.timestamp).num_microseconds().unwrap_or(0) as f64 / 1_000_000.0;
    let count = events.len() as f64;
    let total_bytes = sent + received;
    let avg = if duration_count > 0 { duration_sum / duration_count as f64 } else { 0.0 };
    let stddev = if duration_count < 2 { 0.0 } else { (m2 / duration_count as f64).sqrt() };
    let connection_rate = if span > 0.0 { count / span } else { 0.0 };
    let bytes_rate = if span > 0.0 { total_bytes as f64 / span } else { 0.0 };
    let concentration = port_counts.values().copied().max().unwrap_or(0) as f64 / count;
    let window_start = if events.len() == 1 || first.timestamp == last.timestamp {
        last.timestamp - Duration::seconds(WINDOW_SECONDS)
    } else { first.timestamp };
    let values = [
        count, ports.len() as f64, ips.len() as f64, failed as f64, syn as f64,
        avg, max_duration, min_duration, stddev, sent as f64, received as f64,
        total_bytes as f64 / count, connection_rate, bytes_rate, concentration,
        (ports.len() > 1) as u8 as f64, (ips.len() > 1) as u8 as f64, span,
        last.src_port as f64, last.dst_port as f64,
    ];
    let mut extra = HashMap::new();
    extra.insert("unique_src_ports".into(), json!(src_ports.len()));
    extra.insert("dst_ports_list".into(), json!(ports));
    extra.insert("dst_ips_list".into(), json!(ips));
    let vector = FeatureVector {
        vector_id: Uuid::new_v4(), event_id: last.event_id, created_at: Utc::now(),
        window_start, window_end: last.timestamp, src_ip: last.src_ip.clone(),
        dst_ip: last.dst_ip.clone(), src_port: last.src_port, dst_port: last.dst_port,
        proto: last.protocol.clone(), values, extra,
    };
    vector.validate()?;
    Ok(vector)
}

struct WindowRegistry {
    windows: HashMap<String, Arc<Mutex<SlidingWindow>>>,
    lru: VecDeque<String>,
}
struct FeatureExtractor {
    windows: Mutex<WindowRegistry>,
}
impl FeatureExtractor {
    fn new() -> Self { Self { windows: Mutex::new(WindowRegistry { windows: HashMap::new(), lru: VecDeque::new() }) } }
    fn extract(&self, event: NormalizedEvent) -> Result<FeatureVector, String> {
        let key = event.src_ip.clone();
        let event = Arc::new(event);
        let window = {
            let mut registry = self.windows.lock().map_err(|_| "registry mutex poisoned")?;
            if registry.windows.contains_key(&key) {
                registry.lru.retain(|item| item != &key);
            } else if registry.windows.len() >= MAX_ACTIVE_WINDOWS {
                if let Some(oldest) = registry.lru.pop_front() { registry.windows.remove(&oldest); }
            }
            registry.lru.push_back(key.clone());
            registry.windows.entry(key).or_insert_with(|| Arc::new(Mutex::new(SlidingWindow::new()))).clone()
        };
        let snapshot = {
            let mut state = window.lock().map_err(|_| "window mutex poisoned")?;
            state.add(event.clone());
            state.snapshot(event.timestamp)
        };
        aggregate(&snapshot)
    }
}

fn percentile(samples: &mut [u64], pct: f64) -> f64 {
    if samples.is_empty() { return 0.0; }
    samples.sort_unstable();
    let index = ((samples.len() - 1) as f64 * pct).floor() as usize;
    samples[index] as f64 / 1_000_000.0
}
fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find(|line| line.starts_with("VmHWM:")).map(str::to_owned))
        .and_then(|line| line.split_whitespace().nth(1).and_then(|v| v.parse().ok())).unwrap_or(0)
}
fn worker(count: usize, base: DateTime<Utc>) -> Result<(usize, Vec<u64>, [f64; 23]), String> {
    let extractor = FeatureExtractor::new();
    let mut latencies = Vec::with_capacity(count);
    let mut sums = [0.0_f64; 23];
    let mut processed = 0;
    for seq in 0..count {
        let started = Instant::now();
        let event = NormalizedEvent::new(seq, base)?;
        let vector = extractor.extract(event)?;
        latencies.push(started.elapsed().as_nanos() as u64);
        for (sum, value) in sums.iter_mut().take(20).zip(vector.values) { *sum += value; }
        sums[20] += vector.extra.get("unique_src_ports").and_then(Value::as_u64).unwrap_or(0) as f64;
        sums[21] += vector.extra.get("dst_ports_list").and_then(Value::as_array).map_or(0, |items| items.len()) as f64;
        sums[22] += vector.extra.get("dst_ips_list").and_then(Value::as_array).map_or(0, |items| items.len()) as f64;
        processed += 1;
        black_box((&vector.vector_id, &vector.event_id, &vector.created_at,
            &vector.window_start, &vector.window_end, &vector.src_ip,
            &vector.dst_ip, vector.src_port, vector.dst_port, &vector.proto, &vector.extra));
    }
    Ok((processed, latencies, sums))
}
fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let events: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5000);
    let workers: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    if events == 0 || workers == 0 { return Err("events and workers must be positive".into()); }
    let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().ok_or("invalid base time")?;
    let started = Instant::now();
    let results = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers).map(|_| scope.spawn(move || worker(events, base))).collect();
        handles.into_iter().map(|h| h.join().map_err(|_| "worker panic".to_string())?).collect::<Result<Vec<_>, String>>()
    })?;
    let elapsed = started.elapsed().as_secs_f64();
    let processed: usize = results.iter().map(|r| r.0).sum();
    let mut latencies: Vec<u64> = results.iter().flat_map(|r| r.1.iter().copied()).collect();
    let p50 = percentile(&mut latencies.clone(), 0.50);
    let p95 = percentile(&mut latencies.clone(), 0.95);
    let p99 = percentile(&mut latencies.clone(), 0.99);
    let max_latency = latencies.iter().copied().max().unwrap_or(0) as f64 / 1_000_000.0;
    let mut sums = [0.0_f64; 23];
    for result in &results { for (sum, value) in sums.iter_mut().zip(result.2) { *sum += value; } }
    let names = ["connection_count","unique_dst_ports","unique_dst_ips","failed_connections","syn_count",
        "avg_duration","max_duration","min_duration","std_duration","total_bytes_sent",
        "total_bytes_received","avg_bytes_per_connection","connection_rate","bytes_rate",
        "port_concentration","is_multi_port","is_multi_dst","time_since_first_connection","src_port","dst_port","unique_src_ports","dst_ports_list_len","dst_ips_list_len"];
    let feature_sums: serde_json::Map<String, Value> = names.iter().enumerate()
        .map(|(i, name)| ((*name).to_string(), json!(sums[i]))).collect();
    let report = json!({
        "language":"rust","workers":workers,"offered_events":events*workers,
        "processed_events":processed,"unprocessed_events":events*workers-processed,
        "wall_seconds":elapsed,"throughput_events_per_second":processed as f64/elapsed,
        "latency_ms":{"p50":p50,"p95":p95,"p99":p99,"max":max_latency},
        "peak_rss_kib":peak_rss_kib(),"feature_sums":feature_sums,
        "active_windows":SOURCE_COUNT*workers,"window_events_cap":MAX_EVENTS_PER_WINDOW,
        "source_count_per_worker":SOURCE_COUNT
    });
    println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    Ok(())
}
