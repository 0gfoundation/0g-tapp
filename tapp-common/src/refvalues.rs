//! Published reference values — the digests an audited 0g-tapp CVM image is expected
//! to measure — and matching a node's boot chain against them, here on the client.
//!
//! The same comparison tappscan makes, done locally: the AS is asked only for what
//! nothing else can do (verify the quote's signature chain to Intel, report TCB, replay
//! the event log against the signed RTMRs), and the boot chain is then a pure function
//! of that SIGNED token plus these public files. So a verdict names WHICH image a node
//! runs, a newly published image is recognised without registering anything on the AS,
//! and the reader trusts the AS for the quote — not for what counts as a good image.
//!
//! The rules mirror tappscan's `refvalues.rs` and `../verifier/policy.rego`. They are the
//! security check, not a routing hint — keep the three in step.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const DEFAULT_REPO: &str = "0gfoundation/0g-tapp";
pub const DEFAULT_REF: &str = "dev";
pub const DEFAULT_PATH: &str = "verifier/reference-values";

/// The reference-value key for a UKI is compared against the digest of ANY boot-services
/// application rather than a device-path spelling, so those digests collect under this.
pub const ANY_BSA: &str = "_any_bsa";

/// Digests a node measured, keyed by component.
#[derive(Debug, Default, Clone)]
pub struct Measured(pub BTreeMap<String, BTreeSet<String>>);

impl Measured {
    fn add(&mut self, component: &str, digest: &str) {
        self.0
            .entry(component.to_string())
            .or_default()
            .insert(digest.to_string());
    }

    /// grub images measure shim+grub; UKI images fuse everything into one EFI.
    pub fn boot_format(&self) -> &'static str {
        if self.0.contains_key("grub") {
            "grub"
        } else {
            "uki"
        }
    }

    /// `(component, digest)` pairs in reference-value naming, for printing a measurement
    /// nobody has published yet: the boot-services pseudo-component is shown as `uki` on
    /// a UKI image (its only component) and left out on grub, where those digests are
    /// already listed as shim and grub.
    pub fn as_reference_pairs(&self) -> Vec<(String, String)> {
        let uki = self.boot_format() == "uki";
        self.0
            .iter()
            .filter_map(|(c, ds)| match c.as_str() {
                ANY_BSA if uki => Some(("uki", ds)),
                ANY_BSA => None,
                other => Some((other, ds)),
            })
            .flat_map(|(c, ds)| ds.iter().map(move |d| (c.to_string(), d.clone())))
            .collect()
    }
}

/// The boot-chain digests in the AS token's parsed event log
/// (`ear.veraison.annotated-evidence.tdx.uefi_event_logs`).
///
/// | component        | event                            | matched on                      |
/// |------------------|----------------------------------|---------------------------------|
/// | `shim`           | EV_EFI_BOOT_SERVICES_APPLICATION | device path ~ `shimx64.efi`     |
/// | `grub`           | EV_EFI_BOOT_SERVICES_APPLICATION | device path ~ `grubx64.efi`     |
/// | `kernel`         | EV_IPL                           | string starts `/vmlinuz`        |
/// | `initrd`         | EV_IPL                           | string starts `/initrd`         |
/// | `kernel_cmdline` | EV_IPL                           | string starts `kernel_cmdline:` |
/// | (UKI)            | EV_EFI_BOOT_SERVICES_APPLICATION | any — collected under `ANY_BSA` |
pub fn boot_digests(logs: &[Value]) -> Measured {
    let mut measured = Measured::default();
    for e in logs {
        let Some(digest) = sha384_of(e) else { continue };
        match e.get("type_name").and_then(Value::as_str) {
            Some("EV_EFI_BOOT_SERVICES_APPLICATION") => {
                measured.add(ANY_BSA, digest);
                let paths = e
                    .pointer("/details/device_paths")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase()
                    })
                    .unwrap_or_default();
                if paths.contains("shimx64.efi") {
                    measured.add("shim", digest);
                } else if paths.contains("grubx64.efi") {
                    measured.add("grub", digest);
                }
            }
            Some("EV_IPL") => {
                let s = e
                    .pointer("/details/string")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if s.starts_with("kernel_cmdline:") {
                    measured.add("kernel_cmdline", digest);
                } else if s.starts_with("/vmlinuz") {
                    measured.add("kernel", digest);
                } else if s.starts_with("/initrd") {
                    measured.add("initrd", digest);
                }
            }
            _ => {}
        }
    }
    measured
}

/// Measured tapp operations (domain `tapp.0g.com`) whose body does not hash to the
/// digest that was extended — the AS's own per-event check. Any at all means what the
/// log says tapp did (start_app, claim_config) cannot be believed.
///
/// Firmware events are deliberately not counted: for many of them (a loaded EFI image,
/// the kernel) the extended digest is of the file, not of the event data, so the AS's
/// flag is false on every healthy node.
pub fn replay_mismatches(logs: &[Value]) -> usize {
    logs.iter()
        .filter(|e| e.pointer("/details/data/domain").and_then(Value::as_str) == Some(TAPP_DOMAIN))
        .filter(|e| e.get("digest_matches_event").and_then(Value::as_bool) == Some(false))
        .count()
}

/// Domain every measured tapp runtime operation is tagged with.
const TAPP_DOMAIN: &str = "tapp.0g.com";

fn sha384_of(event: &Value) -> Option<&str> {
    event
        .get("digests")?
        .as_array()?
        .iter()
        .find(|d| d.get("alg").and_then(Value::as_str) == Some("SHA-384"))?
        .get("digest")?
        .as_str()
}

/// One published reference-value file. Its path IS the image label
/// (`<cloud>/<boot format>/<version>[-r<rev>]/<env>.json`).
#[derive(Debug, Clone)]
pub struct RefSet {
    pub label: String,
    /// component → allowed digests, OR-matched (how several accepted `kernel_cmdline`
    /// spellings coexist).
    pub values: BTreeMap<String, Vec<String>>,
}

impl RefSet {
    fn boot_format(&self) -> &'static str {
        if self.values.keys().any(|c| c == "grub" || c == "shim") {
            "grub"
        } else {
            "uki"
        }
    }
}

fn key_to_component(key: &str) -> Option<String> {
    let rest = key.strip_prefix("measurement.")?.strip_suffix(".SHA-384")?;
    Some(match rest {
        "uki" => ANY_BSA.to_string(),
        other => other.to_string(),
    })
}

/// `None` when the file holds no `measurement.*.SHA-384` entries — a README or an
/// unrelated json in the tree is not an error.
pub fn parse_set(label: &str, bytes: &[u8]) -> Option<RefSet> {
    let parsed: BTreeMap<String, Vec<String>> = serde_json::from_slice(bytes).ok()?;
    let values: BTreeMap<String, Vec<String>> = parsed
        .into_iter()
        .filter_map(|(k, v)| {
            let v: Vec<String> = v.into_iter().filter(|s| !s.is_empty()).collect();
            (!v.is_empty()).then(|| key_to_component(&k).map(|c| (c, v)))?
        })
        .collect();
    (!values.is_empty()).then(|| RefSet {
        label: label.to_string(),
        values,
    })
}

/// Every `*.json` under `dir`, recursively, labelled by its path relative to `dir`.
pub fn load_dir(dir: &Path) -> Result<Vec<RefSet>> {
    let mut sets = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)
            .with_context(|| format!("read reference-value dir {}", path.display()))?
        {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
            let label = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().into_owned();
            if let Some(set) = parse_set(&label, &raw) {
                sets.push(set);
            }
        }
    }
    sets.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(sets)
}

/// The reference sets in force for a run, and where they came from — printed with the
/// verdict, because "no published image matches" only means something next to what it
/// was compared against.
pub struct Loaded {
    pub sets: Vec<RefSet>,
    pub source: String,
}

/// A directory of reference values: pinned, offline, nothing changes underneath.
pub fn from_dir(dir: &Path) -> Result<Loaded> {
    let sets = load_dir(dir)?;
    if sets.is_empty() {
        return Err(anyhow!("no reference values under {}", dir.display()));
    }
    Ok(Loaded { sets, source: dir.display().to_string() })
}

/// The reference values published at `git_ref` of `repo`, pinned to the commit it
/// resolves to now. Two GitHub API calls (`GITHUB_TOKEN` is honoured for the rate
/// limit), then the files themselves — cached per commit, since a commit never changes.
pub async fn from_github(repo: &str, git_ref: &str, path: &str) -> Result<Loaded> {
    const API: &str = "https://api.github.com";
    let http = reqwest::Client::builder()
        .user_agent("tapp-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let get = |url: String, accept: &'static str| {
        let mut req = http.get(&url).header("accept", accept);
        if let Some(t) = &token {
            req = req.bearer_auth(t);
        }
        async move {
            let resp = req.send().await.with_context(|| format!("GET {url}"))?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(anyhow!(
                    "GET {url} → {status}: {}",
                    body.chars().take(200).collect::<String>()
                ));
            }
            Ok(body)
        }
    };

    let commit = get(
        format!("{API}/repos/{repo}/commits/{git_ref}"),
        "application/vnd.github.sha",
    )
    .await?
    .trim()
    .to_string();
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("{repo}@{git_ref} did not resolve to a commit"));
    }
    let source = format!("{repo}@{git_ref} ({}):{path}", &commit[..12]);

    let cache = dirs::cache_dir().map(|d| d.join("tapp-cli/reference-values").join(&commit));
    if let Some(dir) = cache.as_deref() {
        if let Ok(sets) = load_dir(dir) {
            if !sets.is_empty() {
                return Ok(Loaded { sets, source });
            }
        }
    }

    let tree: Value = serde_json::from_str(
        &get(
            format!("{API}/repos/{repo}/git/trees/{commit}?recursive=1"),
            "application/vnd.github+json",
        )
        .await?,
    )?;
    if tree.get("truncated").and_then(Value::as_bool) == Some(true) {
        // A truncated tree could silently omit a set, which would read as an unknown
        // image on every node running it.
        return Err(anyhow!("{repo}@{commit} tree came back truncated"));
    }
    let prefix = format!("{}/", path.trim_end_matches('/'));
    let wanted: Vec<String> = tree
        .get("tree")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("unexpected tree response"))?
        .iter()
        .filter(|e| e.get("type").and_then(Value::as_str) == Some("blob"))
        .filter_map(|e| e.get("path")?.as_str()?.strip_prefix(&prefix))
        .filter(|rel| rel.ends_with(".json"))
        .map(str::to_string)
        .collect();

    let mut sets = Vec::new();
    let mut files = Vec::new();
    for rel in &wanted {
        // By commit, not by branch: the ref can move between these requests.
        let bytes = get(
            format!("https://raw.githubusercontent.com/{repo}/{commit}/{prefix}{rel}"),
            "application/octet-stream",
        )
        .await?;
        if let Some(set) = parse_set(rel, bytes.as_bytes()) {
            sets.push(set);
            files.push((rel.clone(), bytes));
        }
    }
    if sets.is_empty() {
        return Err(anyhow!("nothing under {path} in {repo}@{commit} parsed as reference values"));
    }
    sets.sort_by(|a, b| a.label.cmp(&b.label));

    // Best effort: a cache that cannot be written only costs the next run a download.
    if let Some(dir) = cache {
        let tmp = dir.with_extension("tmp");
        let written = files.iter().all(|(rel, bytes)| {
            let p = tmp.join(rel);
            p.parent().map(std::fs::create_dir_all).transpose().is_ok()
                && std::fs::write(&p, bytes).is_ok()
        });
        if !(written && std::fs::rename(&tmp, &dir).is_ok()) {
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }
    Ok(Loaded { sets, source })
}

/// How a node's measurements compare against one reference set.
#[derive(Debug, Clone)]
pub struct SetMatch {
    pub label: String,
    /// (component, matched) in reference-set order.
    pub components: Vec<(String, bool)>,
    /// True only when EVERY component the set constrains matched.
    pub matched: bool,
}

impl SetMatch {
    pub fn hits(&self) -> usize {
        self.components.iter().filter(|(_, ok)| *ok).count()
    }
}

/// Compare against EVERY set, full matches first. Exhaustive on purpose: narrowing by
/// inferred boot format or version could skip the set that would have matched and
/// blame the node for our heuristic.
pub fn match_sets(measured: &Measured, sets: &[RefSet]) -> Vec<SetMatch> {
    let mut out: Vec<SetMatch> = sets
        .iter()
        .map(|set| {
            let components: Vec<(String, bool)> = set
                .values
                .iter()
                .map(|(component, allowed)| {
                    let hit = measured
                        .0
                        .get(component)
                        .map(|m| allowed.iter().any(|a| m.contains(a)))
                        .unwrap_or(false);
                    (component.clone(), hit)
                })
                .collect();
            let matched = !components.is_empty() && components.iter().all(|(_, ok)| *ok);
            SetMatch { label: set.label.clone(), components, matched }
        })
        .collect();
    out.sort_by(|a, b| {
        b.matched
            .cmp(&a.matched)
            .then(b.hits().cmp(&a.hits()))
            .then(a.label.cmp(&b.label))
    });
    out
}

/// The set to point at when nothing matched: same boot format and at least one
/// component in common, or nothing — naming a UKI set as the closest thing to a grub
/// node sends the reader to the wrong file.
pub fn closest<'a>(
    measured: &Measured,
    sets: &[RefSet],
    matches: &'a [SetMatch],
) -> Option<&'a SetMatch> {
    let format = measured.boot_format();
    let comparable: BTreeSet<&str> = sets
        .iter()
        .filter(|s| s.boot_format() == format)
        .map(|s| s.label.as_str())
        .collect();
    matches
        .iter()
        .filter(|m| !m.matched && m.hits() > 0 && comparable.contains(m.label.as_str()))
        .max_by_key(|m| m.hits())
}

/// The boot-chain verdict for one node.
#[derive(Debug, Clone)]
pub enum BootChain {
    /// Reference values were unavailable, so the boot chain was not checked — which is
    /// not the same as checked and failed.
    NotChecked,
    /// Matches this published set.
    Matched(String),
    /// Matches none. `closest` is (label, hits, components) of the nearest comparable set.
    Unknown { closest: Option<(String, usize, usize)> },
}

pub fn identify(measured: &Measured, sets: Option<&[RefSet]>) -> BootChain {
    let Some(sets) = sets else { return BootChain::NotChecked };
    let matches = match_sets(measured, sets);
    if let Some(m) = matches.iter().find(|m| m.matched) {
        return BootChain::Matched(m.label.clone());
    }
    BootChain::Unknown {
        closest: closest(measured, sets, &matches)
            .map(|m| (m.label.clone(), m.hits(), m.components.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(label: &str, pairs: &[(&str, &[&str])]) -> RefSet {
        RefSet {
            label: label.to_string(),
            values: pairs
                .iter()
                .map(|(c, v)| (c.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        }
    }

    fn bsa(digest: &str, path: &str) -> Value {
        json!({"type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
               "digests": [{"alg": "SHA-384", "digest": digest}],
               "details": {"device_paths": [path]}})
    }

    fn ipl(digest: &str, s: &str) -> Value {
        json!({"type_name": "EV_IPL",
               "digests": [{"alg": "SHA-384", "digest": digest}],
               "details": {"string": s}})
    }

    #[test]
    fn the_boot_chain_is_read_from_the_tokens_event_log() {
        let logs = vec![
            bsa("s1", "\\EFI\\BOOT\\shimx64.efi"),
            bsa("g1", "\\EFI\\ubuntu\\grubx64.efi"),
            ipl("k1", "/vmlinuz-6.8.0"),
            ipl("i1", "/initrd.img-6.8.0"),
            ipl("c1", "kernel_cmdline: /vmlinuz root=…"),
        ];
        let m = boot_digests(&logs);
        assert_eq!(m.boot_format(), "grub");
        for (c, d) in [("shim", "s1"), ("grub", "g1"), ("kernel", "k1"), ("initrd", "i1"), ("kernel_cmdline", "c1")] {
            assert!(m.0[c].contains(d), "{c}");
        }
        // grub's boot-services digests are not repeated under a uki name.
        assert!(m.as_reference_pairs().iter().all(|(c, _)| c != "uki"));
    }

    #[test]
    fn a_uki_node_is_matched_on_any_boot_services_digest() {
        let m = boot_digests(&[bsa("other", "\\EFI\\x.efi"), bsa("u1", "\\EFI\\BOOT\\BOOTX64.EFI")]);
        assert_eq!(m.boot_format(), "uki");
        let sets = vec![set("gcp/uki/v0.8.0-r3/dev.json", &[(ANY_BSA, &["u1"])])];
        assert!(matches!(identify(&m, Some(&sets)), BootChain::Matched(l) if l == "gcp/uki/v0.8.0-r3/dev.json"));
        assert!(m.as_reference_pairs().iter().any(|(c, d)| c == "uki" && d == "u1"));
    }

    #[test]
    fn reference_files_map_uki_and_skip_what_is_not_a_measurement() {
        let s = parse_set("a.json", br#"{"measurement.uki.SHA-384":["u1"],"other":["x"]}"#).unwrap();
        assert_eq!(s.values.keys().collect::<Vec<_>>(), vec![ANY_BSA]);
        assert!(parse_set("README.json", br#"{"note":["x"]}"#).is_none());
    }

    #[test]
    fn multi_value_entries_or_match() {
        let mut m = Measured::default();
        m.add("kernel_cmdline", "second");
        let sets = vec![set("s.json", &[("kernel_cmdline", &["first", "second"])])];
        assert!(matches!(identify(&m, Some(&sets)), BootChain::Matched(_)));
    }

    #[test]
    fn no_reference_values_is_not_checked_rather_than_unknown() {
        assert!(matches!(identify(&Measured::default(), None), BootChain::NotChecked));
        assert!(matches!(
            identify(&Measured::default(), Some(&[])),
            BootChain::Unknown { closest: None }
        ));
    }

    #[test]
    fn closest_only_offers_a_comparable_set() {
        let mut m = Measured::default();
        m.add("shim", "s1");
        m.add("grub", "g1");
        m.add("kernel", "k-actual");
        m.add(ANY_BSA, "s1");
        let sets = vec![
            set("ali/uki/v0.3.0/dev.json", &[(ANY_BSA, &["u-other"])]),
            set("gcp/grub/v0.2.0/dev.json", &[("shim", &["s1"]), ("grub", &["g1"]), ("kernel", &["k-pub"])]),
        ];
        match identify(&m, Some(&sets)) {
            BootChain::Unknown { closest: Some((label, 2, 3)) } => assert_eq!(label, "gcp/grub/v0.2.0/dev.json"),
            other => panic!("{other:?}"),
        }
        let uki_only = vec![set("ali/uki/v0.3.0/dev.json", &[(ANY_BSA, &["u-other"])])];
        assert!(matches!(identify(&m, Some(&uki_only)), BootChain::Unknown { closest: None }));
    }

    #[test]
    fn only_tapp_events_that_do_not_replay_are_counted() {
        let tapp = |ok: bool| json!({"digest_matches_event": ok, "details": {"data": {"domain": "tapp.0g.com"}}});
        let logs = vec![
            tapp(true),
            tapp(false),
            // A firmware event's digest is of the file it loaded: false on every healthy node.
            json!({"type_name": "EV_EFI_BOOT_SERVICES_APPLICATION", "digest_matches_event": false}),
            json!({}),
        ];
        assert_eq!(replay_mismatches(&logs), 1);
    }

    #[test]
    fn a_directory_is_read_recursively_and_labelled_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gcp/uki/v0.8.0/dev.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, br#"{"measurement.uki.SHA-384":["u1"]}"#).unwrap();
        std::fs::write(dir.path().join("README.md"), b"not json").unwrap();
        let l = from_dir(dir.path()).unwrap();
        assert_eq!(l.sets.len(), 1);
        assert_eq!(l.sets[0].label, "gcp/uki/v0.8.0/dev.json");
    }
}
