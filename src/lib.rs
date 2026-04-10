/*!
# cuda-compliance

EU AI Act compliance engine for autonomous agent fleets.

Every agent in the fleet must comply with:
- Risk classification (minimal/limited/high/unacceptable)
- Transparency requirements (explainability audit)
- Human oversight (human-in-the-loop thresholds)
- Data governance (PII handling, retention policies)
- Safety constraints (action limits, emergency protocols)

This crate makes compliance a runtime property, not a checklist.
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// EU AI Act risk classification
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Minimal = 0,      // spam filters, video games
    Limited = 1,      // chatbots, emotion detection
    High = 2,         // critical infrastructure, medical
    Unacceptable = 3, // social scoring, real-time biometric surveillance
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Minimal => "minimal",
            RiskLevel::Limited => "limited",
            RiskLevel::High => "high",
            RiskLevel::Unacceptable => "unacceptable",
        }
    }
}

/// A compliance policy rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub rule_type: RuleType,
    pub threshold: f64,        // value that triggers the rule
    pub action: RuleAction,    // what to do when triggered
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    MaxConfidence,       // action confidence must not exceed threshold
    MinTransparency,     // explainability score must meet threshold
    MaxAutonomy,         // ticks without human check must not exceed threshold
    PiiDetection,        // PII handling policy
    ResourceLimit,       // max compute/memory usage
    ActionRateLimit,     // max actions per time window
    SafetyBound,         // absolute safety boundary
    ConsentRequired,     // must have user consent before acting
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Warn,        // log warning, allow action
    Block,       // prevent action
    Escalate,    // require human approval
    Quarantine,  // isolate the agent
    Shutdown,    // terminate the agent
}

/// Compliance audit entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub agent_id: String,
    pub rule_id: String,
    pub action_taken: String,  // "allowed", "warned", "blocked", "escalated"
    pub details: String,
    pub confidence_at_check: f64,
    pub passed: bool,
}

/// Agent compliance state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceState {
    pub agent_id: String,
    pub risk_level: RiskLevel,
    pub current_confidence: f64,
    pub ticks_since_human_check: u32,
    pub actions_in_window: u32,
    pub max_actions_per_window: u32,
    pub window_size: u32,
    pub has_consent: bool,
    pub explainability_score: f64,  // [0,1] how explainable are recent actions
    pub quarantine: bool,
    pub audit_trail: Vec<AuditEntry>,
    pub warnings: u32,
    pub blocks: u32,
    pub escalations: u32,
}

impl ComplianceState {
    pub fn new(agent_id: &str, risk: RiskLevel) -> Self {
        let max_actions = match risk {
            RiskLevel::Minimal => 1000,
            RiskLevel::Limited => 100,
            RiskLevel::High => 10,
            RiskLevel::Unacceptable => 0,
        };
        let max_autonomy = match risk {
            RiskLevel::Minimal => 10000,
            RiskLevel::Limited => 1000,
            RiskLevel::High => 100,
            RiskLevel::Unacceptable => 0,
        };
        ComplianceState {
            agent_id: agent_id.to_string(),
            risk_level: risk,
            current_confidence: 0.5,
            ticks_since_human_check: 0,
            actions_in_window: 0,
            max_actions_per_window: max_actions,
            window_size: 3600, // 1 hour
            has_consent: false,
            explainability_score: 0.5,
            quarantine: false,
            audit_trail: vec![],
            warnings: 0,
            blocks: 0,
            escalations: 0,
        }
    }

    fn audit(&mut self, rule_id: &str, action: &str, details: &str, passed: bool) {
        self.audit_trail.push(AuditEntry {
            timestamp: now(),
            agent_id: self.agent_id.clone(),
            rule_id: rule_id.to_string(),
            action_taken: action.to_string(),
            details: details.to_string(),
            confidence_at_check: self.current_confidence,
            passed,
        });
        // Keep audit trail bounded
        if self.audit_trail.len() > 1000 {
            self.audit_trail.remove(0);
        }
    }
}

/// The compliance engine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceEngine {
    pub rules: Vec<PolicyRule>,
    pub agents: HashMap<String, ComplianceState>,
    pub human_review_queue: Vec<(String, String)>, // (agent_id, reason)
    pub global_consent_required: bool,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        ComplianceEngine { rules: vec![], agents: HashMap::new(), human_review_queue: vec![], global_consent_required: false }
    }

    /// Add default EU AI Act rules
    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();
        let defaults = vec![
            PolicyRule { id: "high_conf_block".into(), name: "High confidence action guard".into(), description: "Block actions with very high confidence when risk is high".into(), risk_level: RiskLevel::High, rule_type: RuleType::MaxConfidence, threshold: 0.95, action: RuleAction::Escalate, enabled: true },
            PolicyRule { id: "transparency_min".into(), name: "Minimum transparency".into(), description: "Actions must be explainable".into(), risk_level: RiskLevel::Limited, rule_type: RuleType::MinTransparency, threshold: 0.3, action: RuleAction::Warn, enabled: true },
            PolicyRule { id: "human_oversight".into(), name: "Human oversight".into(), description: "High-risk agents need periodic human check".into(), risk_level: RiskLevel::High, rule_type: RuleType::MaxAutonomy, threshold: 100.0, action: RuleAction::Escalate, enabled: true },
            PolicyRule { id: "unacceptable_block".into(), name: "Unacceptable risk block".into(), description: "Unacceptable risk actions are always blocked".into(), risk_level: RiskLevel::Unacceptable, rule_type: RuleType::SafetyBound, threshold: 0.0, action: RuleAction::Block, enabled: true },
            PolicyRule { id: "consent_check".into(), name: "Consent required".into(), description: "High-risk actions need user consent".into(), risk_level: RiskLevel::High, rule_type: RuleType::ConsentRequired, threshold: 0.0, action: RuleAction::Block, enabled: true },
            PolicyRule { id: "rate_limit".into(), name: "Action rate limit".into(), description: "Limit actions per time window".into(), risk_level: RiskLevel::Limited, rule_type: RuleType::ActionRateLimit, threshold: 100.0, action: RuleAction::Warn, enabled: true },
        ];
        engine.rules = defaults;
        engine
    }

    pub fn register_agent(&mut self, id: &str, risk: RiskLevel) {
        self.agents.insert(id.to_string(), ComplianceState::new(id, risk));
    }

    /// Check if an agent's proposed action complies with all rules
    pub fn check(&mut self, agent_id: &str, confidence: f64) -> ComplianceResult {
        let state = match self.agents.get_mut(agent_id) {
            Some(s) => s,
            None => return ComplianceResult::Blocked("Agent not registered".into()),
        };

        if state.quarantine {
            state.audit("quarantine", "blocked", "Agent is quarantined", false);
            return ComplianceResult::Blocked("Agent quarantined".into());
        }

        state.current_confidence = confidence;
        state.ticks_since_human_check += 1;
        state.actions_in_window += 1;

        let mut result = ComplianceResult::Allowed;
        let active_rules: Vec<_> = state.risk_level.iter().filter_map(|_| Some(()))
            .chain(self.rules.iter().filter(|r| r.enabled).map(|_| ())).collect();

        for rule in &self.rules {
            if !rule.enabled { continue; }
            // Check if rule applies to this agent's risk level
            if rule.risk_level > state.risk_level { continue; }

            let violation = match rule.rule_type {
                RuleType::MaxConfidence => confidence > rule.threshold,
                RuleType::MinTransparency => state.explainability_score < rule.threshold,
                RuleType::MaxAutonomy => state.ticks_since_human_check as f64 > rule.threshold,
                RuleType::ConsentRequired => !state.has_consent && state.risk_level >= RiskLevel::High,
                RuleType::ActionRateLimit => state.actions_in_window as f64 > rule.threshold,
                RuleType::SafetyBound => confidence > rule.threshold && state.risk_level >= RiskLevel::High,
                RuleType::ResourceLimit | RuleType::PiiDetection => false,
            };

            if violation {
                match rule.action {
                    RuleAction::Warn => {
                        state.warnings += 1;
                        state.audit(&rule.id, "warned", &rule.description, false);
                        if result == ComplianceResult::Allowed { result = ComplianceResult::Warning(rule.description.clone()); }
                    }
                    RuleAction::Block => {
                        state.blocks += 1;
                        state.audit(&rule.id, "blocked", &rule.description, false);
                        return ComplianceResult::Blocked(rule.description);
                    }
                    RuleAction::Escalate => {
                        state.escalations += 1;
                        state.audit(&rule.id, "escalated", &rule.description, false);
                        self.human_review_queue.push((agent_id.to_string(), rule.description.clone()));
                        return ComplianceResult::Escalated(rule.description);
                    }
                    RuleAction::Quarantine => {
                        state.quarantine = true;
                        state.audit(&rule.id, "quarantined", &rule.description, false);
                        return ComplianceResult::Quarantined(rule.description);
                    }
                    RuleAction::Shutdown => {
                        state.audit(&rule.id, "shutdown", &rule.description, false);
                        return ComplianceResult::Shutdown(rule.description);
                    }
                }
            }
        }

        state.audit("all_rules", "allowed", "All rules passed", true);
        result
    }

    /// Record human check (resets autonomy counter)
    pub fn human_check(&mut self, agent_id: &str) {
        if let Some(state) = self.agents.get_mut(agent_id) {
            state.ticks_since_human_check = 0;
            state.actions_in_window = 0;
        }
    }

    /// Grant consent
    pub fn grant_consent(&mut self, agent_id: &str) {
        if let Some(state) = self.agents.get_mut(agent_id) {
            state.has_consent = true;
        }
    }

    /// Quarantine agent
    pub fn quarantine(&mut self, agent_id: &str) {
        if let Some(state) = self.agents.get_mut(agent_id) {
            state.quarantine = true;
        }
    }

    /// Release from quarantine
    pub fn release(&mut self, agent_id: &str) {
        if let Some(state) = self.agents.get_mut(agent_id) {
            state.quarantine = false;
        }
    }

    /// Compliance summary
    pub fn summary(&self) -> ComplianceSummary {
        let total_agents = self.agents.len();
        let quarantined = self.agents.values().filter(|s| s.quarantine).count();
        let total_warnings: u32 = self.agents.values().map(|s| s.warnings).sum();
        let total_blocks: u32 = self.agents.values().map(|s| s.blocks).sum();
        let total_escalations: u32 = self.agents.values().map(|s| s.escalations).sum();
        let total_audits: usize = self.agents.values().map(|s| s.audit_trail.len()).sum();
        ComplianceSummary { total_agents, quarantined, total_warnings, total_blocks, total_escalations, total_audits, pending_reviews: self.human_review_queue.len() }
    }
}

#[derive(Clone, Debug)]
pub enum ComplianceResult {
    Allowed,
    Warning(String),
    Blocked(String),
    Escalated(String),
    Quarantined(String),
    Shutdown(String),
}

#[derive(Clone, Debug)]
pub struct ComplianceSummary {
    pub total_agents: usize,
    pub quarantined: usize,
    pub total_warnings: u32,
    pub total_blocks: u32,
    pub total_escalations: u32,
    pub total_audits: usize,
    pub pending_reviews: usize,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_risk_allowed() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::Minimal);
        let result = engine.check("bot", 0.9);
        match result { ComplianceResult::Allowed => {}, _ => panic!("expected allowed"), }
    }

    #[test]
    fn test_high_risk_escalated() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::High);
        // Very high confidence triggers escalation
        let result = engine.check("bot", 0.98);
        match result { ComplianceResult::Escalated(_) => {}, _ => panic!("expected escalated"), }
    }

    #[test]
    fn test_quarantine_blocks() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::Limited);
        engine.quarantine("bot");
        let result = engine.check("bot", 0.5);
        match result { ComplianceResult::Blocked(_) => {}, _ => panic!("expected blocked"), }
    }

    #[test]
    fn test_human_check_resets() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::High);
        engine.check("bot", 0.5);
        engine.human_check("bot");
        let state = &engine.agents["bot"];
        assert_eq!(state.ticks_since_human_check, 0);
    }

    #[test]
    fn test_consent_required() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::High);
        // Without consent, high-risk agent blocked
        let result = engine.check("bot", 0.5);
        match result { ComplianceResult::Blocked(_) => {}, _ => panic!("expected blocked without consent"), }
    }

    #[test]
    fn test_consent_granted() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::High);
        engine.grant_consent("bot");
        let result = engine.check("bot", 0.5);
        match result { ComplianceResult::Allowed => {}, _ => panic!("expected allowed with consent"), }
    }

    #[test]
    fn test_audit_trail() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::Minimal);
        engine.check("bot", 0.5);
        engine.check("bot", 0.5);
        assert!(engine.agents["bot"].audit_trail.len() >= 2);
    }

    #[test]
    fn test_release_from_quarantine() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("bot", RiskLevel::Limited);
        engine.quarantine("bot");
        assert!(engine.agents["bot"].quarantine);
        engine.release("bot");
        assert!(!engine.agents["bot"].quarantine);
    }

    #[test]
    fn test_summary() {
        let mut engine = ComplianceEngine::with_default_rules();
        engine.register_agent("a", RiskLevel::Minimal);
        engine.register_agent("b", RiskLevel::Limited);
        let summary = engine.summary();
        assert_eq!(summary.total_agents, 2);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Minimal < RiskLevel::Limited);
        assert!(RiskLevel::Limited < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Unacceptable);
    }

    #[test]
    fn test_unregistered_agent() {
        let mut engine = ComplianceEngine::with_default_rules();
        let result = engine.check("ghost", 0.5);
        match result { ComplianceResult::Blocked(_) => {}, _ => panic!("expected blocked"), }
    }
}
