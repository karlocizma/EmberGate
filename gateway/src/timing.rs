//! Bounded response-header timing summaries, distinct from full request lifetimes.
use crate::state::AccessLog;
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const BOUNDS: [f64; 15] = [
    1., 5., 10., 25., 50., 100., 250., 500., 1000., 2500., 5000., 10000., 30000., 60000., 120000.,
];
#[derive(Default)]
pub struct Summary {
    pub groups: BTreeMap<String, Group>,
}
#[derive(Default)]
pub struct Group {
    pub count: u64,
    pub timed: u64,
    pub headers: f64,
    pub duration: f64,
    pub buckets: [u64; 16],
}
pub fn kind(entry: &AccessLog) -> &'static str {
    if entry.client_cancelled {
        "cancelled"
    } else if entry.status >= 500 {
        "server_error"
    } else if entry.status >= 400 {
        "client_error"
    } else if entry.status < 200 && entry.status != 101 {
        "transport_error"
    } else if entry.long_lived {
        "long_lived"
    } else {
        "success"
    }
}
pub fn bucket(value: f64) -> usize {
    BOUNDS
        .iter()
        .position(|upper| value <= *upper)
        .unwrap_or(15)
}
impl Summary {
    pub fn record(&mut self, entry: &AccessLog) {
        self.add(kind(entry), entry.header_latency_ms, entry.latency_ms, 1);
    }
    pub fn add(&mut self, kind: &str, headers: Option<f64>, duration: f64, count: u64) {
        let group = self.groups.entry(kind.into()).or_default();
        group.count += count;
        group.duration += duration;
        if let Some(value) = headers.filter(|v| v.is_finite() && *v >= 0.) {
            group.timed += count;
            group.headers += value * count as f64;
            group.buckets[bucket(value)] += count;
        }
    }
    pub fn json(&self) -> Value {
        let mut result = serde_json::Map::new();
        for kind in [
            "success",
            "long_lived",
            "server_error",
            "client_error",
            "cancelled",
            "transport_error",
        ] {
            let empty = Group::default();
            let group = self.groups.get(kind).unwrap_or(&empty);
            let rank = group.timed.saturating_mul(95).div_ceil(100);
            let mut seen = 0;
            let percentile = group.buckets.iter().position(|count| {
                seen += count;
                seen >= rank && rank > 0
            });
            result.insert(kind.into(),json!({"requests":group.count,"header_samples":group.timed,"avg_headers_ms":if group.timed>0 {Some(group.headers/group.timed as f64)}else{None},"p95_headers_upper_ms":percentile.and_then(|index|BOUNDS.get(index)).copied(),"p95_overflow":percentile==Some(15),"avg_duration_ms":if group.count>0{Some(group.duration/group.count as f64)}else{None}}));
        }
        Value::Object(result)
    }
}
