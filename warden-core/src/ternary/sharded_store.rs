use rand::prelude::*;
use std::collections::HashMap;

use super::ternary_vsa::{bind, cosine, unbind, TernaryVSA};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ShardedStore {
    pub dim: usize,
    pub entities: HashMap<String, Vec<i8>>,
    pub predicates: HashMap<String, Vec<i8>>,
    pub facts: Vec<(String, String, String)>,
    shards: HashMap<String, Vec<f32>>,
    exact: HashMap<String, HashMap<String, Vec<String>>>,
}

pub fn new(dim: usize) -> ShardedStore {
    ShardedStore {
        dim,
        entities: HashMap::new(),
        predicates: HashMap::new(),
        facts: Vec::new(),
        shards: HashMap::new(),
        exact: HashMap::new(),
    }
}

impl ShardedStore {
    pub fn add_fact(&mut self, s: &str, p: &str, o: &str) {
        self.facts
            .push((s.to_string(), p.to_string(), o.to_string()));
        let entry = self.exact.entry(s.to_string()).or_default();
        let objs = entry.entry(p.to_string()).or_default();
        if !objs.contains(&o.to_string()) {
            objs.push(o.to_string());
        }
    }

    pub fn finalize(&mut self, rng: &mut StdRng) {
        let vsa = TernaryVSA { dim: self.dim };
        for (s, p, o) in &self.facts {
            if !self.entities.contains_key(s) {
                self.entities.insert(s.clone(), vsa.random_bipolar(rng));
            }
            if !self.entities.contains_key(o) {
                self.entities.insert(o.clone(), vsa.random_bipolar(rng));
            }
            if !self.predicates.contains_key(p) {
                self.predicates.insert(p.clone(), vsa.random_bipolar(rng));
            }
        }
        let preds: Vec<String> = self.predicates.keys().cloned().collect();
        for p in preds {
            let mut bundle = vec![0.0f32; self.dim];
            for (s, pp, o) in &self.facts {
                if pp == &p {
                    let sv = self.entities.get(s).unwrap();
                    let ov = self.entities.get(o).unwrap();
                    let q = bind(sv, ov);
                    for (i, &v) in q.iter().enumerate() {
                        bundle[i] += v as f32;
                    }
                }
            }
            self.shards.insert(p, bundle);
        }
    }

    pub fn predicates_used_with(&self, entity: &str) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(subj) = self.exact.get(entity) {
            for p in subj.keys() {
                result.push(p.clone());
            }
        }
        result
    }

    pub fn query(&self, s: &str, p: &str, top_k: usize) -> Vec<(String, f32)> {
        if let Some(subj) = self.exact.get(s) {
            if let Some(objs) = subj.get(p) {
                return objs.iter().map(|o| (o.clone(), 1.0f32)).collect();
            }
        }
        let sv = match self.entities.get(s) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let pv = match self.predicates.get(p) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let q = unbind(sv, pv);
        let mut scored: Vec<(String, f32)> = self
            .entities
            .iter()
            .map(|(name, ev)| (name.clone(), cosine(&q, ev)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.truncate(top_k);
        scored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_kb() -> ShardedStore {
        let mut store = new(128);
        store.add_fact("mci", "capital", "moscow");
        store.add_fact("spb", "capital", "spb");
        store.add_fact("mci", "located_in", "russia");
        store.add_fact("spb", "located_in", "russia");
        store.add_fact("russia", "border", "finland");
        store.add_fact("russia", "border", "china");
        let mut rng = StdRng::seed_from_u64(123);
        store.finalize(&mut rng);
        store
    }

    #[test]
    fn query_exact() {
        let res = build_kb().query("mci", "capital", 3);
        assert!(!res.is_empty());
        assert_eq!(res[0].0, "moscow");
        assert!((res[0].1 - 1.0).abs() < 1e-5);
    }

    #[test]
    fn predicates_used() {
        let mut preds = build_kb().predicates_used_with("mci");
        preds.sort();
        assert_eq!(preds, vec!["capital", "located_in"]);
    }
}
