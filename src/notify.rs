//! Pushover notification delivery, with batching and dedup of noise.

use anyhow::{Context, Result};
use tldr_core::diff::Significance;

use crate::config::Config;
use crate::scan::{RunReport, ZoneResult};

/// Deliver notifications for significant changes. Returns the number of
/// messages successfully sent.
pub async fn deliver(
    config: &Config,
    report: &mut RunReport,
    floor: Significance,
) -> Result<usize> {
    if config.notify.dry_run {
        for change in &report.changed {
            if change.significance.at_least(floor) {
                tracing::info!(
                    origin = %change.origin,
                    significance = %change.significance.as_str(),
                    "would notify (dry run)"
                );
            }
        }
        return Ok(0);
    }

    // On the first run against an empty archive every transferable zone is
    // "new"; paging once per zone would be a flood, so summarize instead.
    if report.is_initial {
        if report.changed.is_empty() {
            tracing::info!("initial run: no transferable zones discovered");
        } else {
            tracing::info!(
                zones = report.changed.len(),
                "initial run: baseline established (no per-zone alerts)"
            );
        }
        return Ok(0);
    }
    if !config.notify.enabled {
        return Ok(0);
    }

    let app_token = match std::env::var(&config.notify.app_token_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::warn!(
                variable = %config.notify.app_token_env,
                "notifications enabled but Pushover app token is unset; skipping alerts"
            );
            return Ok(0);
        }
    };
    let user_token = match std::env::var(&config.notify.user_token_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::warn!(
                variable = %config.notify.user_token_env,
                "notifications enabled but Pushover user token is unset; skipping alerts"
            );
            return Ok(0);
        }
    };

    let mut notable: Vec<&ZoneResult> = report
        .changed
        .iter()
        .filter(|c| c.significance.at_least(floor))
        .collect();
    notable.sort_by(|a, b| {
        b.significance
            .cmp(&a.significance)
            .then_with(|| a.origin.cmp(&b.origin))
    });

    if notable.is_empty() {
        tracing::info!("no significant changes to notify");
        return Ok(0);
    }

    let messages = build_messages(&notable, config.notify.message_max_chars);
    let mut sent = 0;
    for message in messages {
        let body = serde_json::json!({
            "token": app_token,
            "user": user_token,
            "title": config.notify.title,
            "message": message,
            "priority": config.notify.priority,
        });
        let response = reqwest::Client::new()
            .post("https://api.pushover.net/1/messages.json")
            .json(&body)
            .send()
            .await
            .context("posting to Pushover")?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("Pushover rejected notification: {status} {text}");
        }
        sent += 1;
    }
    tracing::info!(
        messages = sent,
        changes = notable.len(),
        "notifications sent"
    );
    Ok(sent)
}

/// Build one or more message bodies from notable changes.
fn build_messages(changes: &[&ZoneResult], max_chars: usize) -> Vec<String> {
    let max_chars = max_chars.max(200);
    let mut messages = Vec::new();
    let mut current = String::new();

    for change in changes {
        let line = format_line(change);
        if current.len() + line.len() + 1 > max_chars && !current.is_empty() {
            messages.push(std::mem::take(&mut current));
        }
        current.push_str(&line);
        current.push('\n');
    }
    if !current.is_empty() {
        messages.push(current);
    }
    messages
}

fn format_line(change: &ZoneResult) -> String {
    let tag = match change.significance {
        Significance::High => "HIGH",
        Significance::Medium => "MED",
        Significance::Low => "low",
        Significance::None => "none",
    };
    match &change.diff {
        Some(diff) => format!("[{tag}] {}: {}", change.origin, diff.summary()),
        None => format!("[{tag}] {}: newly transferable", change.origin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Outcome;

    fn change(origin: &str, level: Significance) -> ZoneResult {
        ZoneResult {
            origin: origin.to_string(),
            server: "ns".to_string(),
            outcome: Outcome::Transferred,
            significance: level,
            diff: None,
            entry: None,
        }
    }

    #[test]
    fn messages_split_on_limit() {
        let changes = [
            change("a.", Significance::High),
            change("b.", Significance::High),
            change("c.", Significance::High),
        ];
        let refs: Vec<&ZoneResult> = changes.iter().collect();
        let messages = build_messages(&refs, 200);
        assert!(!messages.is_empty());
        assert!(messages.iter().all(|m| m.len() <= 260));
    }

    #[test]
    fn line_includes_origin() {
        let change = change("example.", Significance::High);
        let line = format_line(&change);
        assert!(line.contains("example."));
        assert!(line.contains("HIGH"));
    }
}
