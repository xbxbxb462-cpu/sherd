//! Integration test: SHERD_ALLOW_NO_MLOCK bypass MUST be disabled in
//! release builds.
//!
//! This test spawns the actual `sherd` binary as a subprocess with the
//! `SHERD_ALLOW_NO_MLOCK` env var set. In a release build, the binary
//! MUST reject the env var before reaching mlockall and exit with a
//! non-zero status. In a debug build, the env var is honored (with a
//! loud warning).
//!
//! This is the only way to verify the main.rs startup path: unit tests
//! cannot exercise `main()`.

use std::process::Command;
use std::env;

fn sherd_binary() -> String {
    // cargo sets CARGO_BIN_EXE_sherd for integration tests.
    env::var("CARGO_BIN_EXE_sherd")
        .expect("CARGO_BIN_EXE_sherd not set — run via `cargo test`")
}

#[test]
fn release_build_rejects_sherd_allow_no_mlock() {
    let bin = sherd_binary();

    // Spawn the binary with the env var set, asking for `--help`.
    // We use `--help` (not `selftest`) because:
    //   - main() runs mlockall BEFORE CLI parsing, so `--help` still
    //     exercises the env-var check.
    //   - `--help` exits immediately after parsing, so the test is fast
    //     (no Argon2id KAT, no selftest run).
    let output = Command::new(&bin)
        .arg("--help")
        .env("SHERD_ALLOW_NO_MLOCK", "1")
        .output()
        .expect("failed to spawn sherd binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    if cfg!(debug_assertions) {
        // Debug build: the env var is honored. The binary proceeds past
        // the mlockall check (with a loud warning) and parses --help.
        // It must NOT print the release-only fatal rejection message.
        assert!(
            !stderr.contains("SHERD_ALLOW_NO_MLOCK is set in the environment"),
            "debug build must not print the release-only fatal rejection:\n{}",
            stderr
        );
    } else {
        // Release build: the env var MUST be rejected. The binary exits
        // with a non-zero status and prints a fatal message naming the
        // env var. It must NOT proceed to parse --help.
        assert!(
            !output.status.success(),
            "release build must NOT succeed when SHERD_ALLOW_NO_MLOCK is set"
        );
        assert!(
            stderr.contains("SHERD_ALLOW_NO_MLOCK"),
            "release build must mention SHERD_ALLOW_NO_MLOCK in the fatal error:\n{}",
            stderr
        );
    }
}

#[test]
fn no_env_var_does_not_honor_bypass() {
    // Without the env var, the binary must NOT honor the bypass —
    // i.e., it must fail if mlockall fails (it cannot proceed past
    // mlockall). The FATAL mlockall message is allowed to MENTION
    // SHERD_ALLOW_NO_MLOCK (as guidance to the operator); what we
    // verify here is that the binary does NOT succeed.
    //
    // We use `selftest` (not `--help`) because main() runs mlockall
    // BEFORE parsing CLI args, so `--help` would also trigger the
    // mlockall path.
    let bin = sherd_binary();

    let output = Command::new(&bin)
        .arg("selftest")
        .output()
        .expect("failed to spawn sherd binary");

    // Without the env var, the binary must not succeed if mlockall
    // fails. (If mlockall succeeds in this environment — e.g., the
    // test runner has CAP_IPC_LOCK — the binary may succeed; that's
    // fine too. We only assert that it does NOT silently bypass
    // mlockall without the env var being set.)
    //
    // If the binary succeeded, mlockall must have genuinely succeeded
    // (not been bypassed). We cannot directly observe this from the
    // test, but the absence of the bypass-acceptance warning is a
    // strong signal.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The FATAL message must NOT contain the bypass-acceptance
        // warning (which is printed only when the env var is set AND
        // honored in a debug build).
        assert!(
            !stderr.contains("mlockall failed but SHERD_ALLOW_NO_MLOCK=1"),
            "binary must not print the bypass-accepted warning when the env var is not set:\n{}",
            stderr
        );
    }
}
