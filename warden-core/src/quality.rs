use crate::pool::QualityMetrics;

pub fn score_speed(m: &QualityMetrics) -> f64 {
    let latency_score = (1000.0 / (m.latency_ms + 10.0)).max(0.0);
    let tp_score = m.throughput_mbps / 1000.0;
    latency_score * 0.7 + tp_score * 0.3
}

pub fn score_stealth(m: &QualityMetrics) -> f64 {
    let base = 50.0 / (m.latency_ms + 10.0);
    let dpi_boost = if m.dpi_resistance { 50.0 } else { 0.0 };
    base + dpi_boost
}

pub fn score_balanced(m: &QualityMetrics) -> f64 {
    0.6 * score_speed(m) + 0.4 * score_stealth(m)
}
