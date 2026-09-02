use rand::distributions::Uniform;
use rand::prelude::*;

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(&x, &y)| x * y).sum()
}

fn relu(x: f32) -> f32 {
    if x > 0.0 {
        x
    } else {
        0.0
    }
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.iter().map(|&e| e / sum).collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FastController {
    layers: Vec<(Vec<f32>, Vec<f32>)>,
    pub in_dim: usize,
    pub hid: usize,
    pub npred: usize,
}

pub fn new(in_dim: usize, hid: usize, npred: usize, rng: &mut StdRng) -> FastController {
    let mut layers = Vec::new();
    let fin = in_dim * 2;
    let scale1 = (2.0f32 / fin as f32).sqrt();
    let range1 = Uniform::from(-scale1..scale1);
    let w1: Vec<f32> = (0..fin * hid).map(|_| range1.sample(rng)).collect();
    let b1: Vec<f32> = vec![0.0; hid];
    layers.push((w1, b1));
    let scale2 = (2.0f32 / hid as f32).sqrt();
    let range2 = Uniform::from(-scale2..scale2);
    let w2: Vec<f32> = (0..hid * npred).map(|_| range2.sample(rng)).collect();
    let b2: Vec<f32> = vec![0.0; npred];
    layers.push((w2, b2));
    FastController {
        layers,
        in_dim,
        hid,
        npred,
    }
}

impl FastController {
    pub fn forward(&self, entity: &[f32], goal: &[f32]) -> Vec<f32> {
        let input: Vec<f32> = entity.iter().chain(goal.iter()).cloned().collect();
        let (ref w1, ref b1) = self.layers[0];
        let mut hidden = vec![0.0f32; self.hid];
        for j in 0..self.hid {
            let col: Vec<f32> = (0..self.in_dim * 2).map(|i| w1[i * self.hid + j]).collect();
            hidden[j] = relu(b1[j] + dot(&col, &input));
        }
        let (ref w2, ref b2) = self.layers[1];
        let mut out = vec![0.0f32; self.npred];
        for j in 0..self.npred {
            let col: Vec<f32> = (0..self.hid).map(|i| w2[i * self.npred + j]).collect();
            out[j] = b2[j] + dot(&col, &hidden);
        }
        out
    }

    pub fn predict_topk(
        &self,
        entity: &[f32],
        goal: &[f32],
        names: &[String],
        k: usize,
    ) -> Vec<(String, f32)> {
        let logits = self.forward(entity, goal);
        let probs = softmax(&logits);
        let n = names.len().min(self.npred);
        let mut idxs: Vec<usize> = (0..n).collect();
        idxs.sort_by(|&a, &b| probs[b].partial_cmp(&probs[a]).unwrap());
        let k = k.min(n);
        idxs[..k]
            .iter()
            .map(|&i| (names[i].clone(), probs[i]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_shape() {
        let mut rng = StdRng::seed_from_u64(99);
        let c = new(16, 32, 8, &mut rng);
        let e = vec![0.0f32; 16];
        let g = vec![0.0f32; 16];
        let out = c.forward(&e, &g);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn predict_topk_sorted() {
        let mut rng = StdRng::seed_from_u64(55);
        let c = new(8, 16, 5, &mut rng);
        let e = vec![0.1f32; 8];
        let g = vec![0.2f32; 8];
        let names: Vec<String> = (0..5).map(|i| format!("p{}", i)).collect();
        let top = c.predict_topk(&e, &g, &names, 3);
        assert_eq!(top.len(), 3);
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1, "should be sorted desc");
        }
    }
}
