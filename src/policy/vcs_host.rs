// These functions are the public API for the VCS fetch client (task 096).
// They are not yet called from main.rs because the fetch client has not been
// implemented — suppress dead_code lint until task 096 wires them in.
#![allow(dead_code)]

use anyhow::{Result, bail};

use crate::config::Config;

/// Extract the bare hostname a git fetch of `url` would actually connect to.
///
/// **SEC-005 invariant.** The host returned here is derived from gix's *own*
/// URL parser (`gix::url::parse`) — the exact same parse gix uses to decide
/// which host to open a socket to.  The policed host is therefore equal **by
/// construction** to the connecting host, so there is no way for the policy to
/// be evaluated against one host (e.g. `github.com`) while gix connects to
/// another (e.g. `evil.com`).  The previous hand-rolled parser split the
/// authority on `['/', '?', '#']`, but gix does **not** treat `#`/`?` as
/// authority terminators — it splits the authority only at the first `/` and
/// then `rsplit_once('@')`.  That divergence let URLs like
/// `https://github.com#@evil.com/x` be policed as `github.com` while gix
/// connected to `evil.com` (an SSRF / allow-list bypass).  Deriving the host
/// from gix eliminates the divergence entirely.
///
/// The returned string is the bare hostname (any `user@` userinfo and `:port`
/// stripped exactly as gix sees them), lowercased.
///
/// Returns `None` for URLs that gix cannot parse, or that gix parses but for
/// which it reports no host component — callers must treat `None` as
/// fail-closed (see [`check_host_policy_for_url`]).
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

    // Derive the host from gix's own parser so the policed host is, by
    // construction, the host gix will connect to (SEC-005).  Any parse error
    // or a parsed URL with no host component fails closed (None).
    let parsed = gix::url::parse(url.into()).ok()?;
    let host = parsed.host()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
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

    // SEC-005-RESIDUAL: the host dep-scan polices MUST equal the host gix
    // actually connects to.  These vectors are the bypass the residual audit
    // found: gix does NOT treat `#`/`?` as authority terminators, so it splits
    // the authority only at the first `/` then `rsplit_once('@')`.  The old
    // hand-rolled parser split on `['/', '?', '#']` first and policed the wrong
    // host (`github.com`) while gix connected to `evil.com`.  Now that
    // `extract_host` derives the host from gix's own parse, both must agree by
    // construction — for each vector we assert `extract_host(url)` equals
    // `gix::url::parse(url).host()`.
    #[test]
    fn sec005_policed_host_matches_gix_parse_tricky_userinfo() {
        let vectors = [
            // `#@evil.com` — gix ignores `#` as a terminator; connects to evil.com.
            "https://github.com#@evil.com/x",
            // `?@evil.com` — gix ignores `?` as a terminator; connects to evil.com.
            "https://github.com?@evil.com/x",
            // git:// variant of the `#@` bypass; connects to evil.internal.
            "git://github.com#@evil.internal/x",
            // `a@b@host` — userinfo `a@b`, host `host` (rsplit_once('@')).
            "https://a@b@host.example.com/x",
        ];
        for url in vectors {
            let ours = extract_host(url)
                .unwrap_or_else(|| panic!("SEC-005: our parser must extract a host for {url:?}"));
            let gix_url = gix::url::parse(url.into())
                .unwrap_or_else(|e| panic!("SEC-005: gix must parse {url:?}: {e}"));
            let gix_host = gix_url
                .host()
                .unwrap_or_else(|| panic!("SEC-005: gix must report a host for {url:?}"))
                .to_ascii_lowercase();
            assert_eq!(
                ours, gix_host,
                "SEC-005: policed host {ours:?} must equal gix's connecting host {gix_host:?} for {url:?}"
            );
        }

        // Explicit regression assertions: the policed host is the host gix
        // CONNECTS to, never the decoy `github.com` the old parser reported.
        assert_eq!(
            extract_host("https://github.com#@evil.com/x").as_deref(),
            Some("evil.com"),
            "SEC-005: `#@evil.com` must police evil.com, not github.com"
        );
        assert_eq!(
            extract_host("https://github.com?@evil.com/x").as_deref(),
            Some("evil.com"),
            "SEC-005: `?@evil.com` must police evil.com, not github.com"
        );
        assert_eq!(
            extract_host("git://github.com#@evil.internal/x").as_deref(),
            Some("evil.internal"),
            "SEC-005: git:// `#@evil.internal` must police evil.internal, not github.com"
        );
    }
}
