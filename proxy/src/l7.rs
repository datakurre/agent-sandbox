/// Match a normalized request path against an `allow_route`/`secret_route`
/// glob pattern.
///
/// `*` matches any run of bytes within a single path segment (never `/`);
/// `**` matches any run of bytes, including `/`, and may match nothing.
/// Matching is anchored at both ends of `path`.
///
/// This is a textbook two-wildcard glob, matched with a bottom-up DP over
/// `(path_idx, pattern_idx)` rather than the single most-recent-star
/// backtrack a hand-rolled version is tempted to use: with only one
/// remembered backtrack point, a pattern like `/**/b/*` can only ever retry
/// the `*`, so when matching it requires crossing a `/` (which `*` cannot
/// do) the whole match fails instead of falling back to let the earlier `**`
/// absorb more of the path. The DP keeps this polynomial
/// (`O(len(path) * len(pattern))`) rather than backtracking exponentially,
/// which matters because `path` comes from an untrusted client.
///
/// Built bottom-up with two rows rather than as a memoized recursion: a
/// recursive version makes one call per byte of `path`, and this runs on
/// connection threads spawned with a small fixed stack
/// (`stack_size(256 * 1024)` in `main.rs`) -- a path a few KB long, well
/// under the 64 KiB head limit, is enough to overflow that stack and abort
/// the whole process, not just the one connection.
pub fn glob_match(path: &str, pattern: &str) -> bool {
    let p = path.as_bytes();
    let t = pattern.as_bytes();
    let n = p.len();
    let m = t.len();

    // `row[j]` is whether `p[i..]` matches `t[j..]`, for the `i` currently
    // being built. Starts as the row for `i == n` (the empty remainder of
    // the path), then each iteration below turns it into the row for the
    // next `i` down, using its own already-computed entries at larger `j`
    // (same row) and the previous row's entries (`i + 1`).
    let mut row = vec![false; m + 1];
    row[m] = true;
    for j in (0..m).rev() {
        row[j] = t[j] == b'*' && row[j + 1];
    }

    for i in (0..n).rev() {
        let mut next = vec![false; m + 1];
        // next[m] stays false: j == m means the pattern is exhausted, which
        // only matches when i == n, and i < n here.
        for j in (0..m).rev() {
            next[j] = if t[j] == b'*' {
                if j + 1 < m && t[j + 1] == b'*' {
                    // `**`: skip it (matches zero bytes here), or consume
                    // p[i] and keep trying to extend it (row[j], the i + 1
                    // entry for the same `**`).
                    next[j + 2] || row[j]
                } else {
                    // `*`: skip it, or consume p[i] as long as it is not a
                    // `/` and keep trying to extend it.
                    next[j + 1] || (p[i] != b'/' && row[j])
                }
            } else {
                p[i] == t[j] && row[j + 1]
            };
        }
        row = next;
    }

    row[0]
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

    #[test]
    fn a_long_path_does_not_overflow_a_connection_threads_small_stack() {
        // Proxy connection threads run with a 256 KiB stack (main.rs). A
        // recursive matcher makes one call per byte of `path`, which
        // overflows that stack -- and aborts the whole process, not just
        // this thread -- well before `path` reaches the 64 KiB head limit a
        // client is allowed to send.
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let matching = format!("/{}/x", "a".repeat(60_000));
                assert!(glob_match(&matching, "/**/x"));
                let non_matching = format!("/{}", "a".repeat(60_000));
                assert!(!glob_match(&non_matching, "/nope"));
            })
            .expect("spawn");
        handle.join().expect("matcher must not overflow the stack");
    }
}
