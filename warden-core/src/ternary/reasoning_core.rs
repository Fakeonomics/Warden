use std::collections::BTreeMap;
use std::path::Path;

use rand::prelude::*;

use crate::error::WardenError;

use super::controller::{new as new_controller, FastController};
use super::sharded_store::{new as new_store, ShardedStore};
use super::ternary_vsa::cosine_f32;

pub type WardenResult<T> = Result<T, WardenError>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Chain {
    nodes: Vec<String>,
    score: f32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReasoningCore {
    pub dim: usize,
    pub store: ShardedStore,
    pub controller: Option<FastController>,
    pub pred_names: Vec<String>,
    pub entity_names: Vec<String>,
    rng_seed: u64,
}

pub fn new(dim: usize) -> ReasoningCore {
    ReasoningCore {
        dim,
        store: new_store(dim),
        controller: None,
        pred_names: Vec::new(),
        entity_names: Vec::new(),
        rng_seed: 0xDEADBEEF,
    }
}

impl ReasoningCore {
    pub fn add_fact(&mut self, s_: &str, p: &str, o: &str) {
        self.store.add_fact(s_, p, o);
    }

    pub fn add_facts(&mut self, facts: &[(&str, &str, &str)]) {
        for (s, p, o) in facts {
            self.store.add_fact(s, p, o);
        }
    }

    pub fn finalize(&mut self) {
        let mut rng = StdRng::seed_from_u64(self.rng_seed);
        self.store.finalize(&mut rng);
        let mut preds: Vec<String> = self.store.predicates.keys().cloned().collect();
        preds.sort();
        self.pred_names = preds;
        let mut ents: Vec<String> = self.store.entities.keys().cloned().collect();
        ents.sort();
        self.entity_names = ents;
        let npred = self.pred_names.len().max(1);
        self.controller = Some(new_controller(self.dim, self.dim / 2, npred, &mut rng));
    }

    pub fn query(&self, s: &str, p: &str, top_k: usize) -> Vec<String> {
        self.store
            .query(s, p, top_k)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    pub fn reason(&self, s: &str, p: &str, max_hops: usize) -> Vec<String> {
        let mut visited = vec![s.to_string()];
        let mut cur = s.to_string();
        for _ in 0..max_hops {
            let res = self.store.query(&cur, p, 1);
            if res.is_empty() {
                break;
            }
            let next = res[0].0.clone();
            if visited.contains(&next) {
                break;
            }
            visited.push(next.clone());
            cur = next;
        }
        visited
    }

    fn entity_vec(&self, name: &str) -> Option<Vec<f32>> {
        self.store
            .entities
            .get(name)
            .map(|v| v.iter().map(|&x| x as f32).collect())
    }

    fn pred_vec(&self, name: &str) -> Option<Vec<f32>> {
        self.store
            .predicates
            .get(name)
            .map(|v| v.iter().map(|&x| x as f32).collect())
    }

    fn score_predicates(
        &self,
        entity: &str,
        goal_pred: &str,
        reachable: &[String],
    ) -> Vec<(String, f32)> {
        let goal_v = match self.pred_vec(goal_pred) {
            Some(v) => v,
            None => return reachable.iter().map(|p| (p.clone(), 0.0)).collect(),
        };
        let ent_v = match self.entity_vec(entity) {
            Some(v) => v,
            None => return reachable.iter().map(|p| (p.clone(), 0.0)).collect(),
        };
        let bonus: f32 = 1.0;
        let mut scored: Vec<(String, f32)> = reachable
            .iter()
            .map(|p| {
                let pv = self.pred_vec(p).unwrap_or_else(|| vec![0.0; self.dim]);
                let bound: Vec<f32> = ent_v.iter().zip(pv.iter()).map(|(&e, &q)| e * q).collect();
                let mut score = cosine_f32(&bound, &goal_v);
                if p == goal_pred {
                    score += bonus;
                }
                (p.clone(), score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored
    }

    pub fn controlled_reason(
        &self,
        entity: &str,
        goal_pred: &str,
        max_hops: usize,
        beam: usize,
    ) -> Vec<String> {
        let _ = match self.entity_vec(entity) {
            Some(v) => v,
            None => return vec![entity.to_string()],
        };
        let mut beam_chains = vec![Chain {
            nodes: vec![entity.to_string()],
            score: 0.0,
        }];
        for _hop in 0..max_hops {
            let mut candidates: Vec<Chain> = Vec::new();
            for chain in &beam_chains {
                let cur = chain.nodes.last().unwrap();
                let reachable = self.store.predicates_used_with(cur);
                if reachable.is_empty() {
                    candidates.push(chain.clone());
                    continue;
                }
                let scored_preds = self.score_predicates(cur, goal_pred, &reachable);
                let mut found = false;
                for (pred_name, pred_score) in &scored_preds {
                    let objs = self.store.query(cur, pred_name, 1);
                    if let Some((obj, _)) = objs.first() {
                        if chain.nodes.contains(obj) {
                            continue;
                        }
                        let mut new_chain = chain.clone();
                        new_chain.nodes.push(obj.clone());
                        new_chain.score += pred_score + 0.01 * objs[0].1;
                        candidates.push(new_chain);
                        found = true;
                    }
                }
                if !found {
                    candidates.push(chain.clone());
                }
            }
            candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
            candidates.dedup_by(|a, b| a.nodes == b.nodes);
            candidates.truncate(beam);
            beam_chains = candidates;
            if beam_chains.is_empty() {
                break;
            }
        }
        beam_chains
            .first()
            .map(|c| c.nodes.clone())
            .unwrap_or_else(|| vec![entity.to_string()])
    }

    pub fn save(&self, path: &Path) -> WardenResult<()> {
        let bytes = bincode::serialize(self).map_err(|e| WardenError::Other(e.to_string()))?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn get_stats(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("dim".into(), self.dim.to_string());
        m.insert("facts".into(), self.store.facts.len().to_string());
        m.insert("entities".into(), self.entity_names.len().to_string());
        m.insert("predicates".into(), self.pred_names.len().to_string());
        m.insert(
            "controller".into(),
            if self.controller.is_some() {
                "yes"
            } else {
                "no"
            }
            .into(),
        );
        m
    }
}

pub fn load(path: &Path) -> WardenResult<ReasoningCore> {
    let bytes = std::fs::read(path)?;
    let core: ReasoningCore =
        bincode::deserialize(&bytes).map_err(|e| WardenError::Other(e.to_string()))?;
    Ok(core)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_kb() -> ReasoningCore {
        let mut core = new(256);
        let facts = [
            ("mci", "capital", "moscow"),
            ("spb", "capital", "spb"),
            ("kazan", "capital", "kazan"),
            ("mci", "located_in", "rusa"),
            ("spb", "located_in", "rusa"),
            ("rusa", "border", "finland"),
            ("rusa", "border", "china"),
            ("finland", "located_in", "europe"),
            ("china", "located_in", "asia"),
            ("rusa", "risk", "high"),
        ];
        core.add_facts(&facts);
        core.finalize();
        core
    }

    #[test]
    fn controlled_reason_reaches_moscow() {
        let core = build_kb();
        println!("=== KB FACTS ===");
        for (s, p, o) in &core.store.facts {
            println!("  {} -- {} -- {}", s, p, o);
        }
        let chain = core.controlled_reason("mci", "capital", 2, 3);
        println!("=== controlled_reason(mci, capital) chain ===");
        for (i, n) in chain.iter().enumerate() {
            println!("  [{}] {}", i, n);
        }
        assert_eq!(chain.last().unwrap(), "moscow");
    }

    #[test]
    fn save_load_roundtrip() {
        let core = build_kb();
        let path = std::env::temp_dir().join("warden_ternary_test.bin");
        core.save(&path).unwrap();
        let loaded = load(&path).unwrap();
        let res = loaded.query("mci", "capital", 3);
        println!("=== save/load roundtrip query(mci, capital) ===");
        println!("  {:?}", res);
        assert!(!res.is_empty());
        assert_eq!(res[0], "moscow");
        let _ = std::fs::remove_file(&path);
    }
}
