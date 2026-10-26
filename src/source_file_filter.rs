use std::path::Path;

/// Identify the filename pattern used by a few packages for documentation
/// shipped with a code extension. Callers must still inspect its contents:
/// README.js can be a legitimate executable entrypoint.
pub(crate) fn is_dependency_readme_candidate(path: &Path, code_extensions: &[&str]) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some((stem, extension)) = name.rsplit_once('.') else {
        return false;
    };
    stem.eq_ignore_ascii_case("readme") && code_extensions.contains(&extension)
}

#[cfg(test)]
mod tests {
    use super::is_dependency_readme_candidate;
    use std::path::Path;

    #[test]
    fn recognizes_only_readme_files_with_scanned_code_extensions() {
        let extensions = ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];
        for file in ["README.js", "readme.mjs", "ReadMe.tsx"] {
            assert!(
                is_dependency_readme_candidate(Path::new(file), &extensions),
                "{file}"
            );
        }
        for file in [
            "README.md",
            "README.d.ts",
            "README.js.map",
            "readme-helper.js",
            "runtime.js",
        ] {
            assert!(
                !is_dependency_readme_candidate(Path::new(file), &extensions),
                "{file}"
            );
        }
    }
}
