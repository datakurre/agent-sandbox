/// Match a normalized request path against an `allow_route`/`secret_route`
/// glob pattern.
///
/// `*` matches any run of bytes within a single path segment (never `/`);
/// `**` matches any run of bytes, including `/`, and may match nothing.
/// Matching is anchored at both ends of `path`.
///
/// This is a textbook two-wildcard glob, matched with a memoized recursion
/// over `(path_idx, pattern_idx)` rather than the single most-recent-star
/// backtrack a hand-rolled version is tempted to use: with only one
/// remembered backtrack point, a pattern like `/**/b/*` can only ever retry
/// the `*`, so when matching it requires crossing a `/` (which `*` cannot
/// do) the whole match fails instead of falling back to let the earlier `**`
/// absorb more of the path. Memoizing on both indices keeps this polynomial
/// (`O(len(path) * len(pattern))`) rather than backtracking exponentially,
/// which matters because `path` comes from an untrusted client.
pub fn glob_match(path: &str, pattern: &str) -> bool {
    let p = path.as_bytes();
    let t = pattern.as_bytes();
    let mut memo = vec![vec![None; t.len() + 1]; p.len() + 1];
    matches(p, t, 0, 0, &mut memo)
}

fn matches(p: &[u8], t: &[u8], pi: usize, ti: usize, memo: &mut [Vec<Option<bool>>]) -> bool {
    if let Some(result) = memo[pi][ti] {
        return result;
    }
    let result = if ti == t.len() {
        pi == p.len()
    } else if t[ti] == b'*' {
        if ti + 1 < t.len() && t[ti + 1] == b'*' {
            // `**`: any run of bytes, including `/`, possibly empty.
            matches(p, t, pi, ti + 2, memo)
                || (pi < p.len() && matches(p, t, pi + 1, ti, memo))
        } else {
            // `*`: any run of bytes within a segment, possibly empty.
            matches(p, t, pi, ti + 1, memo)
                || (pi < p.len() && p[pi] != b'/' && matches(p, t, pi + 1, ti, memo))
        }
    } else {
        pi < p.len() && p[pi] == t[ti] && matches(p, t, pi + 1, ti + 1, memo)
    };
    memo[pi][ti] = Some(result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("/foo/bar", "/*/*"));
        assert!(glob_match("/foo/bar", "/**"));
        assert!(!glob_match("/foo/bar/baz", "/*/*"));
        assert!(glob_match("/foo/bar/baz", "/*/**"));
        assert!(glob_match(
            "/user/repo.git/git-upload-pack",
            "/*/*.git/git-upload-pack"
        ));
    }

    #[test]
    fn a_single_star_after_double_star_can_backtrack_into_an_earlier_double_star() {
        // The reported false negative: with only one remembered backtrack
        // point, a hand-rolled matcher commits the `**` to "a/b/c" greedily,
        // then fails the trailing `/*` because it cannot make `*` cross the
        // `/` before "b/d" -- and never retries the `**` with a shorter
        // match to let `*` absorb "d" instead.
        assert!(glob_match("/a/b/c/b/d", "/**/b/*"));
        assert!(glob_match("/x/y/releases/v1", "/**/releases/*"));
        assert!(!glob_match("/x/releases/v1/extra", "/**/releases/*"));
    }

    #[test]
    fn boundary_cases() {
        assert!(glob_match("/", "/**"));
        assert!(glob_match("/a", "/*"));
        assert!(!glob_match("/a/b", "/*"));
        // `**` attached to a literal segment, not standing alone, keeps its
        // current meaning: any bytes at all, including `/`.
        assert!(glob_match("/foo/bar", "/foo**"));
    }

    #[test]
    fn a_pathological_pattern_does_not_blow_up() {
        let pattern = "/**/**/**/**/**/**/**/**/**/**/x";
        let path = format!("/{}", "a/".repeat(2000));
        let start = std::time::Instant::now();
        assert!(!glob_match(&path, pattern));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "glob_match took too long: {:?}",
            start.elapsed()
        );
    }
}
