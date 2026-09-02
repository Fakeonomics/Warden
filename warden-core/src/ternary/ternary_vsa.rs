use rand::distributions::Uniform;
use rand::prelude::*;

pub struct TernaryVSA {
    pub dim: usize,
}

pub fn new(dim: usize) -> TernaryVSA {
    TernaryVSA { dim }
}

impl TernaryVSA {
    pub fn random_vec(&self, rng: &mut StdRng) -> Vec<i8> {
        let range = Uniform::from(0..3u8);
        (0..self.dim)
            .map(|_| match range.sample(rng) {
                0 => -1,
                1 => 0,
                _ => 1,
            })
            .collect()
    }

    pub fn random_bipolar(&self, rng: &mut StdRng) -> Vec<i8> {
        let range = Uniform::from(0..2u8);
        (0..self.dim)
            .map(|_| if range.sample(rng) == 0 { -1 } else { 1 })
            .collect()
    }
}

pub fn bind(a: &[i8], b: &[i8]) -> Vec<i8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x * y).collect()
}

pub fn unbind(a: &[i8], b: &[i8]) -> Vec<i8> {
    bind(a, b)
}

pub fn unify(vectors: &[&[i8]]) -> Vec<i8> {
    if vectors.is_empty() {
        return Vec::new();
    }
    let dim = vectors[0].len();
    let mut sum = vec![0i32; dim];
    for v in vectors {
        for (i, &x) in v.iter().enumerate() {
            sum[i] += x as i32;
        }
    }
    sum.iter()
        .map(|&s| {
            if s > 0 {
                1
            } else if s < 0 {
                -1
            } else {
                0
            }
        })
        .collect()
}

pub fn cosine(a: &[i8], b: &[i8]) -> f32 {
    if a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        dot += (x as f32) * (y as f32);
        na += (x as f32) * (x as f32);
        nb += (y as f32) * (y as f32);
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

pub fn cosine_f32(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

pub fn cleanup(q: &[i8], cands: &[(Vec<i8>, &str)]) -> (String, f32) {
    let mut best_score = f32::NEG_INFINITY;
    let mut best_name = String::new();
    for (v, name) in cands {
        let s = cosine(q, v);
        if s > best_score {
            best_score = s;
            best_name = name.to_string();
        }
    }
    (best_name, best_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_unbind_identity() {
        let mut rng = StdRng::seed_from_u64(42);
        let vsa = TernaryVSA { dim: 64 };
        let x = vsa.random_bipolar(&mut rng);
        let y = vsa.random_bipolar(&mut rng);
        let bound = bind(&x, &y);
        let recovered = unbind(&bound, &y);
        assert_eq!(
            recovered, x,
            "bind/unbind is self-inverse identity on dense bipolar"
        );
    }

    #[test]
    fn cosine_self_neg() {
        let mut rng = StdRng::seed_from_u64(7);
        let vsa = TernaryVSA { dim: 128 };
        let x = vsa.random_vec(&mut rng);
        let self_sim = cosine(&x, &x);
        assert!(
            (self_sim - 1.0).abs() < 1e-5,
            "cosine(x,x) should be 1.0, got {}",
            self_sim
        );
        let neg: Vec<i8> = x.iter().map(|&v| -v).collect();
        let neg_sim = cosine(&x, &neg);
        assert!(
            (neg_sim + 1.0).abs() < 1e-5,
            "cosine(x,-x) should be -1.0, got {}",
            neg_sim
        );
    }

    #[test]
    fn cleanup_picks_best() {
        let mut rng = StdRng::seed_from_u64(11);
        let vsa = TernaryVSA { dim: 64 };
        let target = vsa.random_vec(&mut rng);
        let noise1 = vsa.random_vec(&mut rng);
        let noise2 = vsa.random_vec(&mut rng);
        let cands = vec![
            (noise1, "wrong1"),
            (target.clone(), "correct"),
            (noise2, "wrong2"),
        ];
        let (name, score) = cleanup(&target, &cands);
        assert_eq!(name, "correct");
        assert!((score - 1.0).abs() < 1e-5);
    }
}
