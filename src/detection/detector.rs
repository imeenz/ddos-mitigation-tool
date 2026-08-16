#[derive(Debug)]
pub struct TrafficBaseline {
    samples: Vec<f64>,
    max_samples: usize,
}

impl TrafficBaseline {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples),
            max_samples,
        }
    }

    pub fn add_sample(&mut self, packets_per_second: u64) {
        if self.samples.len() >= self.max_samples {
            self.samples.remove(0);
        }

        self.samples.push(packets_per_second as f64);
    }

    pub fn is_ready(&self) -> bool {
        self.samples.len() >= self.max_samples
    }

    pub fn mean(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        Some(self.samples.iter().sum::<f64>() / self.samples.len() as f64)
    }

    pub fn standard_deviation(&self) -> Option<f64> {
        let mean = self.mean()?;

        let variance = self
            .samples
            .iter()
            .map(|sample| {
                let difference = sample - mean;
                difference * difference
            })
            .sum::<f64>()
            / self.samples.len() as f64;

        Some(variance.sqrt())
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnomalyResult {
    pub current_value: f64,
    pub z_score: f64,
    pub source_concentration: f64,
    pub destination_port_concentration: f64,
    pub anomaly_score: f64,
    pub anomalous: bool,
}

pub fn evaluate(
    baseline: &TrafficBaseline,
    current_packets_per_second: u64,
    source_concentration: f64,
    destination_port_concentration: f64,
    threshold: f64,
) -> Option<AnomalyResult> {
    let mean = baseline.mean()?;
    let standard_deviation = baseline.standard_deviation()?;

    let current_value = current_packets_per_second as f64;

    let z_score = if standard_deviation == 0.0 {
        if current_value > mean { threshold } else { 0.0 }
    } else {
        (current_value - mean) / standard_deviation
    };

    // Normalize the traffic anomaly component to 0.0–1.0.
    let traffic_score = if z_score <= 0.0 {
        0.0
    } else {
        (z_score / threshold).clamp(0.0, 1.0)
    };

    // Concentration values are already expected to be 0.0–1.0.
    let source_score = source_concentration.clamp(0.0, 1.0);

    let port_score = destination_port_concentration.clamp(0.0, 1.0);

    // Weighted combined anomaly score.
    let anomaly_score = (traffic_score * 0.60) + (source_score * 0.20) + (port_score * 0.20);

    Some(AnomalyResult {
        current_value,
        z_score,
        source_concentration,
        destination_port_concentration,
        anomaly_score,
        anomalous: anomaly_score >= 0.80,
    })
}

#[derive(Debug)]
pub struct DetectionEngine {
    baseline: TrafficBaseline,
    threshold: f64,
}

impl DetectionEngine {
    pub fn new(baseline_samples: usize, threshold: f64) -> Self {
        Self {
            baseline: TrafficBaseline::new(baseline_samples),
            threshold,
        }
    }

    pub fn process(
        &mut self,
        packets_per_second: u64,
        source_concentration: f64,
        destination_port_concentration: f64,
    ) -> Option<AnomalyResult> {
        if !self.baseline.is_ready() {
            self.baseline.add_sample(packets_per_second);
            return None;
        }

        let result = evaluate(
            &self.baseline,
            packets_per_second,
            source_concentration,
            destination_port_concentration,
            self.threshold,
        );

        self.baseline.add_sample(packets_per_second);

        result
    }

    pub fn baseline_ready(&self) -> bool {
        self.baseline.is_ready()
    }

    pub fn sample_count(&self) -> usize {
        self.baseline.sample_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_calculates_mean() {
        let mut baseline = TrafficBaseline::new(5);

        baseline.add_sample(100);
        baseline.add_sample(110);
        baseline.add_sample(120);
        baseline.add_sample(130);
        baseline.add_sample(140);

        assert_eq!(baseline.mean(), Some(120.0));
    }

    #[test]
    fn baseline_becomes_ready_after_required_samples() {
        let mut baseline = TrafficBaseline::new(3);

        assert!(!baseline.is_ready());

        baseline.add_sample(100);
        baseline.add_sample(110);

        assert!(!baseline.is_ready());

        baseline.add_sample(120);

        assert!(baseline.is_ready());
    }

    #[test]
    fn baseline_keeps_only_recent_samples() {
        let mut baseline = TrafficBaseline::new(3);

        baseline.add_sample(100);
        baseline.add_sample(110);
        baseline.add_sample(120);
        baseline.add_sample(200);

        assert_eq!(baseline.mean(), Some(143.33333333333334));
    }

    #[test]
    fn detects_anomalous_traffic() {
        let mut baseline = TrafficBaseline::new(5);

        baseline.add_sample(100);
        baseline.add_sample(105);
        baseline.add_sample(110);
        baseline.add_sample(95);
        baseline.add_sample(100);

        let result = evaluate(&baseline, 200, 0.50, 0.80, 3.0).unwrap();

        assert!(result.anomalous);
        assert!(result.z_score > 3.0);
        assert!(result.anomaly_score >= 0.80);
        assert_eq!(result.current_value, 200.0);
        assert_eq!(result.source_concentration, 0.50);
        assert_eq!(result.destination_port_concentration, 0.80);
    }

    #[test]
    fn normal_traffic_is_not_anomalous() {
        let mut baseline = TrafficBaseline::new(5);

        baseline.add_sample(100);
        baseline.add_sample(105);
        baseline.add_sample(110);
        baseline.add_sample(95);
        baseline.add_sample(100);

        let result = evaluate(&baseline, 105, 0.50, 0.40, 3.0).unwrap();

        assert!(!result.anomalous);
        assert!(result.anomaly_score < 0.80);
    }

    #[test]
    fn evaluation_requires_a_baseline() {
        let baseline = TrafficBaseline::new(5);

        let result = evaluate(&baseline, 500, 0.50, 0.80, 3.0);

        assert!(result.is_none());
    }

    #[test]
    fn detection_engine_learns_before_detecting() {
        let mut engine = DetectionEngine::new(3, 3.0);

        assert!(!engine.baseline_ready());
        assert_eq!(engine.sample_count(), 0);

        assert!(engine.process(100, 0.50, 0.40).is_none());
        assert_eq!(engine.sample_count(), 1);

        assert!(engine.process(105, 0.50, 0.40).is_none());
        assert_eq!(engine.sample_count(), 2);

        assert!(engine.process(110, 0.50, 0.40).is_none());
        assert!(engine.baseline_ready());
        assert_eq!(engine.sample_count(), 3);

        let result = engine.process(105, 0.50, 0.40);

        assert!(result.is_some());
    }

    #[test]
    fn detection_engine_detects_anomaly_after_learning() {
        let mut engine = DetectionEngine::new(5, 3.0);

        engine.process(100, 0.50, 0.40);
        engine.process(105, 0.50, 0.40);
        engine.process(110, 0.50, 0.40);
        engine.process(95, 0.50, 0.40);
        engine.process(100, 0.50, 0.40);

        let result = engine.process(500, 0.50, 0.80).unwrap();

        assert!(result.anomalous);
        assert!(result.z_score > 3.0);
        assert!(result.anomaly_score >= 0.80);
        assert_eq!(result.current_value, 500.0);
        assert_eq!(result.destination_port_concentration, 0.80);
    }

    #[test]
    fn detection_engine_accepts_normal_traffic() {
        let mut engine = DetectionEngine::new(5, 3.0);

        engine.process(100, 0.50, 0.40);
        engine.process(105, 0.50, 0.40);
        engine.process(110, 0.50, 0.40);
        engine.process(95, 0.50, 0.40);
        engine.process(100, 0.50, 0.40);

        let result = engine.process(105, 0.50, 0.40).unwrap();

        assert!(!result.anomalous);
        assert!(result.anomaly_score < 0.80);
    }

    #[test]
    fn combined_score_detects_multiple_signals() {
        let mut baseline = TrafficBaseline::new(5);

        baseline.add_sample(100);
        baseline.add_sample(100);
        baseline.add_sample(100);
        baseline.add_sample(100);
        baseline.add_sample(100);

        let result = evaluate(&baseline, 100, 0.95, 0.95, 3.0).unwrap();

        assert!(!result.anomalous);
        assert!(result.anomaly_score >= 0.30);
    }
}
