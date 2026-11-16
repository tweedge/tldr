//! Pushover notification delivery.
//!
//! Notifications are driven by [`Significance`], not raw record counts, and are
//! chunked so a burst of changes (for example during a major re-delegation)
//! arrives as a small number of messages rather than hundreds.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use pushover_rs::{send_pushover_request, MessageBuilder};
use tldr_core::diff::Significance;

use crate::config::{Config, NotifyConfig};
use crate::scan::{RunReport, ZoneResult};

/// Result of attempting delivery.
#[derive(Debug, Default)]
pub struct DeliveryResult {
    /// Number of messages delivered successfully.
    pub sent: usize,
    /// Errors encountered while sending chunks.
    pub errors: Vec<String>,
}

/// Deliver notifications for significant changes.
pub async fn deliver(
    config: &Config,
    report: &mut RunReport,
    floor: Significance,
) -> Result<DeliveryResult> {
    let mut result = DeliveryResult::default();

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
        return Ok(result);
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
        return Ok(result);
    }

    if !config.notify.enabled {
        return Ok(result);
    }

    let Some((app_token, user_token)) = pushover_tokens(&config.notify)? else {
        return Ok(result);
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
        return Ok(result);
    }

    let notifier = Notifier {
        app_token,
        user_token,
        settings: config.notify.clone(),
    };
    result = notifier.send(&notable).await;
    tracing::info!(
        messages = result.sent,
        changes = notable.len(),
        errors = result.errors.len(),
        "notification delivery complete"
    );
    Ok(result)
}

/// Send a single test message so delivery can be verified without waiting for a
/// real change. Returns a human-readable description of what happened.
pub async fn send_test(settings: &NotifyConfig) -> Result<String> {
    if settings.dry_run {
        return Ok("dry run: would send a test notification".to_string());
    }
    if !settings.enabled {
        return Ok("notifications are disabled in config; nothing sent".to_string());
    }
    let Some((app_token, user_token)) = pushover_tokens(settings)? else {
        return Ok("Pushover credentials missing; nothing sent".to_string());
    };
    let notifier = Notifier {
        app_token,
        user_token,
        settings: settings.clone(),
    };
    let message =
        "TLDR test notification. If you received this, alerts from TLDR are wired up correctly.";
    notifier
        .send_one(&format!("{} test", settings.title), message)
        .await?;
    Ok("test notification sent".to_string())
}

/// Send an operational alert (e.g. the health checker saw a stale heartbeat).
/// Uses high priority so it is not lost among normal change notifications.
pub async fn send_alert(settings: &NotifyConfig, message: &str) -> Result<()> {
    if settings.dry_run {
        tracing::info!(%message, "would send alert (dry run)");
        return Ok(());
    }
    let Some((app_token, user_token)) = pushover_tokens(settings)? else {
        return Ok(());
    };
    let mut settings = settings.clone();
    if settings.priority.is_none() {
        settings.priority = Some(1);
    }
    let notifier = Notifier {
        app_token,
        user_token,
        settings,
    };
    notifier
        .send_one(&format!("{} ALERT", notifier.settings.title), message)
        .await
}

fn pushover_tokens(settings: &NotifyConfig) -> Result<Option<(String, String)>> {
    let app_token = match std::env::var(&settings.app_token_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::warn!(
                variable = %settings.app_token_env,
                "notifications enabled but Pushover app token is unset; skipping alerts"
            );
            return Ok(None);
        }
    };
    let user_token = match std::env::var(&settings.user_token_env) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::warn!(
                variable = %settings.user_token_env,
                "notifications enabled but Pushover user token is unset; skipping alerts"
            );
            return Ok(None);
        }
    };
    Ok(Some((app_token, user_token)))
}

struct Notifier {
    app_token: String,
    user_token: String,
    settings: NotifyConfig,
}

impl Notifier {
    async fn send(&self, changes: &[&ZoneResult]) -> DeliveryResult {
        let mut result = DeliveryResult::default();
        let chunks = self.chunk(changes);
        let total = chunks.len();

        for (index, chunk) in chunks.iter().enumerate() {
            let message = self.render_message(chunk, index + 1, total);
            let title = if total == 1 {
                self.settings.title.clone()
            } else {
                format!("{} ({}/{})", self.settings.title, index + 1, total)
            };

            match self.send_one(&title, &message).await {
                Ok(()) => {
                    result.sent += 1;
                    tracing::info!(
                        "sent Pushover message {}/{} with {} change(s)",
                        index + 1,
                        total,
                        chunk.len()
                    );
                }
                Err(error) => {
                    let error = format!("Pushover chunk {}/{} failed: {error:#}", index + 1, total);
                    tracing::warn!("{error}");
                    result.errors.push(error);
                }
            }

            if index + 1 < total {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        result
    }

    fn chunk<'a>(&self, changes: &'a [&ZoneResult]) -> Vec<Vec<&'a ZoneResult>> {
        let budget = self.settings.message_max_chars.max(200).saturating_sub(80);
        let mut chunks = Vec::new();
        let mut current = Vec::new();
        let mut current_len = 0usize;

        for change in changes {
            let line_len = format_line(change).len() + 1;
            if !current.is_empty() && current_len + line_len > budget {
                chunks.push(std::mem::take(&mut current));
                current_len = 0;
            }
            current_len += line_len;
            current.push(*change);
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }

    fn render_message(&self, chunk: &[&ZoneResult], part: usize, total: usize) -> String {
        let header = if total == 1 {
            "Significant zone changes:\n".to_owned()
        } else {
            format!("Significant zone changes ({part}/{total}):\n")
        };
        let mut message = header;
        for change in chunk {
            message.push_str(&format_line(change));
            message.push('\n');
        }
        while message.len() > self.settings.message_max_chars.max(200) {
            if message.pop().is_none() {
                break;
            }
        }
        message
    }

    async fn send_one(&self, title: &str, message: &str) -> Result<()> {
        let mut builder =
            MessageBuilder::new(&self.user_token, &self.app_token, message).set_title(title);
        if let Some(device) = &self.settings.device {
            builder = builder.set_device(device);
        }
        if let Some(priority) = self.settings.priority {
            builder = builder.set_priority(priority);
        }
        let payload = builder.build();

        let response =
            tokio::time::timeout(Duration::from_secs(30), send_pushover_request(payload))
                .await
                .map_err(|_| anyhow!("Pushover request timed out"))?
                .map_err(|error| anyhow!("{error}"))?;

        // A 200 response can still carry status 0 (bad token, invalid user), so
        // check the body rather than the HTTP status.
        if response.status != 1 {
            let errors = response
                .errors
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>()
                .join("; ");
            bail!("Pushover rejected the message: {errors}");
        }
        Ok(())
    }
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

    fn notifier(max_chars: usize) -> Notifier {
        Notifier {
            app_token: "app".to_owned(),
            user_token: "user".to_owned(),
            settings: NotifyConfig {
                title: "TLDR".to_owned(),
                message_max_chars: max_chars,
                ..NotifyConfig::default()
            },
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
        let chunks = notifier(200).chunk(&refs);
        assert!(!chunks.is_empty());
        let total = chunks.len();
        for (index, chunk) in chunks.iter().enumerate() {
            let message = notifier(200).render_message(chunk, index + 1, total);
            assert!(message.len() <= 200);
        }
    }

    #[test]
    fn line_includes_origin() {
        let change = change("example.", Significance::High);
        let line = format_line(&change);
        assert!(line.contains("example."));
        assert!(line.contains("HIGH"));
    }
}
