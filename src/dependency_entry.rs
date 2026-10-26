//! Exact dependency-source location, not a behavioral ownership certificate.
//! Keep this leaf free of parser/runtime dependencies so its refusal cases can
//! be checked offline even when the complete matcher cannot be built.

/// Match the package/version and entire package-relative path emitted by
/// discover_dependencies. Its ten-hex suffix identifies an installed root;
/// it must not be confused with part of a version or a path suffix.
fn same_entry_path(label: &str, root_key: &str, file: &str) -> bool {
    let Some((identity, relative)) = label.split_once(':') else {
        return false;
    };
    if identity
        .rfind('@')
        .is_none_or(|at| at == 0 || at + 1 == identity.len())
        || relative
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
        || relative.contains('\\')
    {
        return false;
    }
    let prefix = format!("npm/{identity}-");
    let Some(tail) = file.strip_prefix(&prefix) else {
        return false;
    };
    let Some((root_hash, path)) = tail.split_once('/') else {
        return false;
    };
    if root_key.len() != 10
        || !root_key.bytes().all(|b| b.is_ascii_hexdigit())
        || root_hash != root_key
    {
        return false;
    }
    // An empty selected runtime root (or an entry outside it) is emitted as
    // `npm/<key>//index.js`; all other path components stay exact.
    path.strip_prefix('/').unwrap_or(path) == relative
}

/// Select only a unique, byte-authenticated file in the exact package entry.
/// The installed-root locator must match; duplicate sources at that root stay
/// ambiguous. This does not certify the owner or its dependency closure.
pub(crate) fn unique_entry_source<'a>(
    label: &str,
    entry_sha256: &str,
    root_key: &str,
    files: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<usize> {
    if entry_sha256.len() != 64 || !entry_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut selected = None;
    for (index, (file, source_sha256)) in files.into_iter().enumerate() {
        if source_sha256 == entry_sha256 && same_entry_path(label, root_key, file) {
            if selected.is_some() {
                return None;
            }
            selected = Some(index);
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const ROOT: &str = "0123456789";
    #[test]
    fn different_package_same_filename_is_not_selected() {
        let files = [
            ("npm/other@1-0123456789//index.js", SHA),
            ("npm/pkg@1-0123456789//index.js", SHA),
        ];
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, files),
            Some(1)
        );
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, [files[0]]),
            None
        );
    }
    #[test]
    fn exact_scoped_package_and_version_are_required() {
        let files = [
            (
                "npm/@scope/other@2.4.0-0123456789/esm/runtime/entry.js",
                SHA,
            ),
            (
                "npm/@scope/runtime@2.3.0-0123456789/esm/runtime/entry.js",
                SHA,
            ),
            (
                "npm/@scope/runtime@2.4.0-0123456789/esm/runtime/entry.js",
                SHA,
            ),
        ];
        assert_eq!(
            unique_entry_source(
                "@scope/runtime@2.4.0:esm/runtime/entry.js",
                SHA,
                ROOT,
                files
            ),
            Some(2)
        );
    }
    #[test]
    fn matching_suffix_does_not_match_another_entry() {
        let files = [("npm/pkg@1-0123456789/lib/index.js", SHA)];
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, files),
            None
        );
        assert_eq!(
            unique_entry_source("pkg@1:lib/index.js", SHA, ROOT, files),
            Some(0)
        );
    }
    #[test]
    fn changed_entry_bytes_are_refused() {
        assert_eq!(
            unique_entry_source(
                "pkg@1:index.js",
                SHA,
                ROOT,
                [("npm/pkg@1-0123456789//index.js", OTHER)]
            ),
            None
        );
    }
    #[test]
    fn exact_installed_root_is_required() {
        let files = [
            ("npm/pkg@1-abcdef0123//index.js", SHA),
            ("npm/pkg@1-0123456789//index.js", SHA),
        ];
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, files),
            Some(1)
        );
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, "abcdef0123", files),
            Some(0)
        );
    }
    #[test]
    fn duplicate_sources_at_the_selected_root_stay_ambiguous() {
        let a = ("npm/pkg@1-0123456789//index.js", SHA);
        let b = ("npm/pkg@1-0123456789/index.js", SHA);
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, [a, b]),
            None
        );
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, [b, a]),
            None
        );
    }
    #[test]
    fn discovery_order_does_not_change_selection() {
        let a = ("npm/other@1-0123456789//index.js", SHA);
        let b = ("npm/pkg@1-0123456789//index.js", SHA);
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, [a, b]),
            Some(1)
        );
        assert_eq!(
            unique_entry_source("pkg@1:index.js", SHA, ROOT, [b, a]),
            Some(0)
        );
    }
    #[test]
    fn malformed_and_traversing_paths_are_refused() {
        for label in [
            "pkg:index.js",
            "@scope:index.js",
            "pkg@1:",
            "pkg@1:/index.js",
            "pkg@1:../index.js",
            "pkg@1:lib/./index.js",
            "pkg@1:lib//index.js",
            "pkg@1:lib\\index.js",
        ] {
            assert_eq!(
                unique_entry_source(label, SHA, ROOT, [("npm/pkg@1-0123456789//index.js", SHA)]),
                None,
                "{label}"
            );
        }
    }
    #[test]
    fn malformed_root_and_missing_hash_are_refused() {
        for file in [
            "npm/pkg@1//index.js",
            "npm/pkg@1-not-a-hash//index.js",
            "npm/pkg@10-0123456789//index.js",
            "npm/pkg@1-0123456789///index.js",
        ] {
            assert_eq!(
                unique_entry_source("pkg@1:index.js", SHA, ROOT, [(file, SHA)]),
                None
            );
        }
        for root in ["", "not-a-hash", "012345678"] {
            assert_eq!(
                unique_entry_source(
                    "pkg@1:index.js",
                    SHA,
                    root,
                    [("npm/pkg@1-0123456789//index.js", SHA)]
                ),
                None
            );
        }
        assert_eq!(unique_entry_source("pkg@1:index.js", "", ROOT, []), None);
    }
    #[test]
    fn prerelease_and_external_entry_are_preserved() {
        assert_eq!(
            unique_entry_source(
                "pkg@1.0.0-beta-2:entry.js",
                SHA,
                ROOT,
                [("npm/pkg@1.0.0-beta-2-0123456789//entry.js", SHA)]
            ),
            Some(0)
        );
    }
}
