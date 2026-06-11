// These functions are the public API for the VCS fetch client (task 096).
// They are not yet called from main.rs because the fetch client has not been
// implemented — suppress dead_code lint until task 096 wires them in.
#![allow(dead_code)]

use anyhow::{Result, bail};

use crate::config::Config;

/// Extract the bare hostname from a VCS URL.
///
/// Handles common schemes (https://, ssh://, git://) as well as SCP-style
/// git URLs (`user@host:path`).  The returned string has any `user@` prefix
/// and `:port` suffix stripped, leaving only the hostname.
///
/// Returns `None` for URLs that cannot be parsed or that contain no
/// recognisable host component — callers must treat `None` as fail-closed.
///
/// # Examples
///
/// ```
/// use dep_scan::policy::vcs_host::extract_host;
/// assert_eq!(extract_host("https://example.com/repo"), Some("example.com".to_string()));
/// assert_eq!(extract_host("not-a-url"), None);
/// ```
pub fn extract_host(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }

    // Try to parse as a scheme-based URL (https://, ssh://, git://, etc.)
    if let Some(without_scheme) = strip_scheme(url) {
        // `without_scheme` is everything after "scheme://"
        // Extract the authority (host[:port]) — ends at '/', '?', '#', or end-of-string.
        let authority = without_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(without_scheme);

        if authority.is_empty() {
            return None;
        }

        // Strip user@ prefix if present.
        let host_and_port = if let Some(at_pos) = authority.rfind('@') {
            &authority[at_pos + 1..]
        } else {
            authority
        };

        // Strip :port suffix if present, but be careful not to strip an IPv6
        // address bracket (we don't support IPv6 in this task — fail-closed).
        let host = strip_port(host_and_port)?;

        if host.is_empty() {
            return None;
        }

        return Some(host.to_ascii_lowercase());
    }

    // Not a scheme-based URL.
    // Check for SCP-style: user@host:path  (no double-slash after colon)
    // Example: git@github.com:user/repo.git
    // The colon must not be followed by '//' (that would be a scheme we already handled).
    if let Some(colon_pos) = url.find(':') {
        let after_colon = &url[colon_pos + 1..];
        if !after_colon.starts_with("//") {
            // Looks like SCP-style.
            let before_colon = &url[..colon_pos];
            // Require something before the colon (the host, possibly with user@).
            if before_colon.is_empty() {
                return None;
            }
            let host_part = if let Some(at_pos) = before_colon.rfind('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            if host_part.is_empty() {
                return None;
            }
            return Some(host_part.to_ascii_lowercase());
        }
    }

    // Cannot parse as any recognisable URL form.
    None
}

/// Strip a URL scheme prefix (`scheme://`) and return everything after it.
///
/// Returns `None` if the URL does not contain `://`.
fn strip_scheme(url: &str) -> Option<&str> {
    let pos = url.find("://")?;
    // Validate the scheme: must consist of ASCII alphanumeric or '+', '-', '.'
    // characters (per RFC 3986 §3.1). If the "scheme" contains invalid chars
    // such as spaces, reject it.
    let scheme = &url[..pos];
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    Some(&url[pos + 3..])
}

/// Strip a trailing `:port` suffix from a host string.
///
/// Returns the host without the port as a `&str`.  Returns `None` if the
/// remaining host would be empty.  Does not attempt to validate the port
/// number — any string after the last `:` is treated as a port token so that
/// non-numeric values (e.g. malformed input) are still stripped, leaving the
/// host.
///
/// IPv6 addresses in brackets (`[::1]`) are intentionally unsupported:
/// passing one returns `None` (fail-closed).
fn strip_port(host_and_port: &str) -> Option<&str> {
    // Reject IPv6 bracket notation — fail-closed per task spec.
    if host_and_port.starts_with('[') {
        return None;
    }

    if let Some(colon_pos) = host_and_port.rfind(':') {
        let host = &host_and_port[..colon_pos];
        if host.is_empty() { None } else { Some(host) }
    } else {
        // No colon at all: the whole string is the host.
        Some(host_and_port)
    }
}

/// Check whether a bare hostname is permitted by the VCS host policy in
/// `config`.
///
/// Rules (applied in order):
///
/// 1. **Deny list wins first** — if `config.vcs.denied_hosts` is non-empty and
///    contains `host` (case-insensitive), return `Err`.
/// 2. **Allow list** — if `config.vcs.allowed_hosts` is non-empty and does
///    *not* contain `host` (case-insensitive), return `Err`.
/// 3. Otherwise return `Ok(())`.
///
/// Empty `allowed_hosts` **and** empty `denied_hosts` means any host is
/// permitted (open posture — operators configure restrictions explicitly).
pub fn check_host_policy(host: &str, config: &Config) -> Result<()> {
    let host_lower = host.to_ascii_lowercase();

    // Deny list takes precedence over allow list.
    if !config.vcs.denied_hosts.is_empty() {
        for denied in &config.vcs.denied_hosts {
            if denied.to_ascii_lowercase() == host_lower {
                bail!(
                    "VCS host '{}' is on the denied_hosts list and cannot be fetched",
                    host
                );
            }
        }
    }

    // Allow list: if non-empty, host must appear in it.
    if !config.vcs.allowed_hosts.is_empty() {
        let permitted = config
            .vcs
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.to_ascii_lowercase() == host_lower);
        if !permitted {
            bail!(
                "VCS host '{}' is not in the allowed_hosts list; \
                 add it to [vcs] allowed_hosts in .dep-scan.toml to permit this host",
                host
            );
        }
    }

    Ok(())
}

/// Check whether the host of `url` is permitted by the VCS host policy.
///
/// Wraps [`extract_host`] + [`check_host_policy`].  Fails closed if the
/// host cannot be extracted — a URL whose origin cannot be determined is
/// never silently permitted.
///
/// This is the function the VCS fetch client (task 096) calls before
/// initiating any network operation.
pub fn check_host_policy_for_url(url: &str, config: &Config) -> Result<()> {
    match extract_host(url) {
        Some(host) => check_host_policy(&host, config),
        None => bail!(
            "Cannot determine host from VCS URL '{}'; \
             refusing to fetch from an unresolvable origin (fail-closed)",
            url
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, VcsConfig};

    /// Helper: build a Config with the given VCS allow/deny lists.
    fn config_with(allowed: Vec<&str>, denied: Vec<&str>) -> Config {
        Config {
            vcs: VcsConfig {
                allowed_hosts: allowed.into_iter().map(|s| s.to_string()).collect(),
                denied_hosts: denied.into_iter().map(|s| s.to_string()).collect(),
                ..VcsConfig::default()
            },
            ..Config::default()
        }
    }

    // ---- extract_host tests ----

    // T-095-06: Host is extracted from https://github.com/user/repo
    #[test]
    fn t095_06_extract_host_https() {
        assert_eq!(
            extract_host("https://github.com/user/repo"),
            Some("github.com".to_string()),
            "T-095-06"
        );
    }

    // T-095-07: user@ is stripped from ssh://git@gitlab.com/user/repo.git
    #[test]
    fn t095_07_extract_host_ssh_user_at() {
        assert_eq!(
            extract_host("ssh://git@gitlab.com/user/repo.git"),
            Some("gitlab.com".to_string()),
            "T-095-07"
        );
    }

    // T-095-08: Port is stripped from https://enterprise.example.com:8080/repo
    #[test]
    fn t095_08_extract_host_with_port() {
        assert_eq!(
            extract_host("https://enterprise.example.com:8080/repo"),
            Some("enterprise.example.com".to_string()),
            "T-095-08"
        );
    }

    // T-095-09: Malformed URL with no recognisable host returns None
    #[test]
    fn t095_09_extract_host_malformed_returns_none() {
        assert_eq!(extract_host("not-a-url"), None, "T-095-09");
    }

    // T-095-10: Empty URL string returns None
    #[test]
    fn t095_10_extract_host_empty_returns_none() {
        assert_eq!(extract_host(""), None, "T-095-10");
    }

    // ---- allow list tests ----

    // T-095-11: Empty allowed_hosts + empty denied_hosts → any host permitted
    #[test]
    fn t095_11_empty_lists_allow_any_host() {
        let config = config_with(vec![], vec![]);
        assert!(
            check_host_policy("github.com", &config).is_ok(),
            "T-095-11: empty lists must allow any host"
        );
    }

    // T-095-12: Host on allowed_hosts is permitted
    #[test]
    fn t095_12_host_on_allow_list_permitted() {
        let config = config_with(vec!["github.com"], vec![]);
        assert!(
            check_host_policy("github.com", &config).is_ok(),
            "T-095-12: host on allow list must be permitted"
        );
    }

    // T-095-13: Host NOT on allowed_hosts is rejected when list is non-empty
    #[test]
    fn t095_13_host_not_on_allow_list_rejected() {
        let config = config_with(vec!["github.com"], vec![]);
        let result = check_host_policy("evil.example.com", &config);
        assert!(
            result.is_err(),
            "T-095-13: host not on allow list must be Err"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("evil.example.com"),
            "T-095-13: error must mention the host, got: {msg}"
        );
        assert!(
            msg.contains("allowed_hosts"),
            "T-095-13: error must mention allowed_hosts, got: {msg}"
        );
    }

    // T-095-14: allowed_hosts check is case-insensitive
    #[test]
    fn t095_14_allow_list_case_insensitive() {
        let config = config_with(vec!["GitHub.com"], vec![]);
        assert!(
            check_host_policy("github.com", &config).is_ok(),
            "T-095-14: allow list check must be case-insensitive"
        );
    }

    // ---- deny list tests ----

    // T-095-15: Host on denied_hosts is rejected regardless of allow list
    #[test]
    fn t095_15_host_on_deny_list_rejected() {
        let config = config_with(vec![], vec!["evil.example.com"]);
        let result = check_host_policy("evil.example.com", &config);
        assert!(result.is_err(), "T-095-15: host on deny list must be Err");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("evil.example.com"),
            "T-095-15: error must mention the host, got: {msg}"
        );
        assert!(
            msg.contains("denied_hosts"),
            "T-095-15: error must mention denied_hosts, got: {msg}"
        );
    }

    // T-095-16: Deny list takes precedence over allow list
    #[test]
    fn t095_16_deny_takes_precedence_over_allow() {
        let config = config_with(vec!["evil.example.com"], vec!["evil.example.com"]);
        let result = check_host_policy("evil.example.com", &config);
        assert!(
            result.is_err(),
            "T-095-16: deny list must take precedence over allow list"
        );
    }

    // T-095-17: Host not on deny list (and no allow list restriction) is permitted
    #[test]
    fn t095_17_host_not_on_deny_list_permitted() {
        let config = config_with(vec![], vec!["evil.example.com"]);
        assert!(
            check_host_policy("github.com", &config).is_ok(),
            "T-095-17: host not on deny list (no allow restriction) must be permitted"
        );
    }

    // ---- fail-closed for URL tests ----

    // T-095-18: URL with no parseable host is rejected (fail-closed)
    #[test]
    fn t095_18_unparseable_url_rejected() {
        let config = Config::default();
        let result = check_host_policy_for_url("not-a-url", &config);
        assert!(
            result.is_err(),
            "T-095-18: URL with no parseable host must be Err (fail-closed)"
        );
    }

    // T-095-19: Empty URL is rejected (fail-closed)
    #[test]
    fn t095_19_empty_url_rejected() {
        let config = Config::default();
        let result = check_host_policy_for_url("", &config);
        assert!(
            result.is_err(),
            "T-095-19: empty URL must be Err (fail-closed)"
        );
    }
}
