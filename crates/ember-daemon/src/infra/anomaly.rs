use chrono::{Duration, Utc};
use serde::Serialize;

use crate::infra::store::{DaemonStore, StoreError};

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub id: String,
    pub agent_id: String,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    BurstActivity,
    UnusualDomain,
    AfterHours,
    HighDenialRate,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl DaemonStore {
    pub fn detect_anomalies(&self) -> Result<Vec<Anomaly>, StoreError> {
        let mut anomalies = Vec::new();

        // Burst: >20 events in 5 minutes per agent
        let five_min_ago = (Utc::now() - Duration::minutes(5)).to_rfc3339();
        let mut stmt = self.conn().prepare(
            "SELECT agent_id, COUNT(*) as cnt FROM audit_log \
             WHERE timestamp > ?1 AND agent_id IS NOT NULL \
             GROUP BY agent_id HAVING cnt > 20",
        )?;
        let bursts = stmt.query_map(rusqlite::params![five_min_ago], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for burst in bursts {
            let (agent_id, count) = burst?;
            anomalies.push(Anomaly {
                id: format!("anomaly-{}", uuid::Uuid::new_v4()),
                agent_id: agent_id.clone(),
                anomaly_type: AnomalyType::BurstActivity,
                description: format!("{count} events in 5 minutes"),
                severity: Severity::High,
                detected_at: Utc::now().to_rfc3339(),
            });
        }

        // High denial rate: >3 denied in 1 hour
        let one_hour_ago = (Utc::now() - Duration::hours(1)).to_rfc3339();
        let mut stmt2 = self.conn().prepare(
            "SELECT agent_id, COUNT(*) as cnt FROM audit_log \
             WHERE timestamp > ?1 AND outcome = 'denied' AND agent_id IS NOT NULL \
             GROUP BY agent_id HAVING cnt > 3",
        )?;
        let denials = stmt2.query_map(rusqlite::params![one_hour_ago], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for denial in denials {
            let (agent_id, count) = denial?;
            anomalies.push(Anomaly {
                id: format!("anomaly-{}", uuid::Uuid::new_v4()),
                agent_id,
                anomaly_type: AnomalyType::HighDenialRate,
                description: format!("{count} denied requests in 1 hour"),
                severity: Severity::Medium,
                detected_at: Utc::now().to_rfc3339(),
            });
        }

        Ok(anomalies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::store::DaemonStore;

    #[test]
    fn no_events_returns_no_anomalies() {
        let store = DaemonStore::open_in_memory().unwrap();
        let anomalies = store.detect_anomalies().unwrap();
        assert!(anomalies.is_empty());
    }

    #[test]
    fn burst_activity_detected_when_over_threshold() {
        let store = DaemonStore::open_in_memory().unwrap();
        for _ in 0..21 {
            store
                .log_event(
                    Some("agent-burst"),
                    "credential.access",
                    None,
                    "allowed",
                    None,
                )
                .unwrap();
        }
        let anomalies = store.detect_anomalies().unwrap();
        let burst = anomalies
            .iter()
            .find(|a| matches!(a.anomaly_type, AnomalyType::BurstActivity));
        assert!(burst.is_some());
        let b = burst.unwrap();
        assert_eq!(b.agent_id, "agent-burst");
        assert!(matches!(b.severity, Severity::High));
    }

    #[test]
    fn high_denial_rate_detected_when_over_threshold() {
        let store = DaemonStore::open_in_memory().unwrap();
        for _ in 0..4 {
            store
                .log_event(
                    Some("agent-denier"),
                    "credential.access",
                    None,
                    "denied",
                    None,
                )
                .unwrap();
        }
        let anomalies = store.detect_anomalies().unwrap();
        let denial = anomalies
            .iter()
            .find(|a| matches!(a.anomaly_type, AnomalyType::HighDenialRate));
        assert!(denial.is_some());
        let d = denial.unwrap();
        assert_eq!(d.agent_id, "agent-denier");
        assert!(matches!(d.severity, Severity::Medium));
    }

    #[test]
    fn only_anomalous_agent_flagged_not_normal_one() {
        let store = DaemonStore::open_in_memory().unwrap();
        // normal agent: 2 denied events (below threshold of 3)
        for _ in 0..2 {
            store
                .log_event(
                    Some("agent-normal"),
                    "credential.access",
                    None,
                    "denied",
                    None,
                )
                .unwrap();
        }
        // anomalous agent: 4 denied events (above threshold)
        for _ in 0..4 {
            store
                .log_event(Some("agent-bad"), "credential.access", None, "denied", None)
                .unwrap();
        }
        let anomalies = store.detect_anomalies().unwrap();
        assert!(anomalies.iter().all(|a| a.agent_id != "agent-normal"));
        assert!(anomalies.iter().any(|a| a.agent_id == "agent-bad"));
    }

    #[test]
    fn burst_below_threshold_not_flagged() {
        let store = DaemonStore::open_in_memory().unwrap();
        for _ in 0..20 {
            store
                .log_event(Some("agent-ok"), "credential.access", None, "allowed", None)
                .unwrap();
        }
        let anomalies = store.detect_anomalies().unwrap();
        let burst = anomalies
            .iter()
            .find(|a| matches!(a.anomaly_type, AnomalyType::BurstActivity));
        assert!(burst.is_none());
    }
}
