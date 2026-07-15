//! Context-aware score enhancement.
//!
//! Port of `presidio_analyzer.context_aware_enhancers.LemmaContextAwareEnhancer`.
//! If a supportive context word (e.g. "card" near a credit-card match) appears in
//! the token window around an entity, its score is boosted.

use crate::entities::RecognizerResult;
use crate::nlp::NlpArtifacts;

pub struct LemmaContextAwareEnhancer {
    /// Added to the score when a supportive context word is found.
    pub context_similarity_factor: f64,
    /// Floor applied to an entity's score once context support is found.
    pub min_score_with_context: f64,
    /// Number of tokens before the entity to inspect.
    pub prefix_count: usize,
    /// Number of tokens after the entity to inspect.
    pub suffix_count: usize,
}

impl Default for LemmaContextAwareEnhancer {
    fn default() -> Self {
        Self {
            context_similarity_factor: 0.35,
            min_score_with_context: 0.4,
            prefix_count: 5,
            suffix_count: 0,
        }
    }
}

impl LemmaContextAwareEnhancer {
    pub fn enhance(&self, results: &mut [RecognizerResult], nlp: &NlpArtifacts) {
        for r in results.iter_mut() {
            if r.context.is_empty() || r.score >= 1.0 {
                continue;
            }
            let ctx: Vec<String> = r.context.iter().map(|w| w.to_lowercase()).collect();
            if let Some(hit) = self.find_supportive_word(nlp, r.start, r.end, &ctx) {
                let mut new_score = (r.score + self.context_similarity_factor).min(1.0);
                if new_score < self.min_score_with_context {
                    new_score = self.min_score_with_context;
                }
                if let Some(expl) = r.analysis_explanation.as_mut() {
                    expl.score_context_improvement = new_score - r.score;
                    expl.supportive_context_word = Some(hit.clone());
                    expl.score = new_score;
                }
                r.score = new_score;
            }
        }
    }

    fn find_supportive_word(
        &self,
        nlp: &NlpArtifacts,
        start: usize,
        end: usize,
        ctx: &[String],
    ) -> Option<String> {
        // Index of the first token that starts at/after the entity end.
        let after_idx = nlp
            .tokens
            .iter()
            .position(|t| t.start >= end)
            .unwrap_or(nlp.tokens.len());
        // Tokens strictly before the entity start.
        let before_end = nlp.tokens.iter().filter(|t| t.end <= start).count();

        let prefix_lo = before_end.saturating_sub(self.prefix_count);
        let suffix_hi = (after_idx + self.suffix_count).min(nlp.tokens.len());

        let window = nlp.tokens[prefix_lo..before_end]
            .iter()
            .chain(nlp.tokens[after_idx..suffix_hi].iter());

        for tok in window {
            if ctx.iter().any(|c| c == &tok.lemma) {
                return Some(tok.lemma.clone());
            }
        }
        None
    }
}
