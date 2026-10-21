//! End-to-end tests of the `agat` binary: the operator contract (exit
//! codes, stateless scans, output formats, config errors, model packs,
//! schema) exercised the way an operator or pipeline would.
//!
//! The model is trained on generated benign inputs (text and structured
//! bytes), so the tests need no fixtures.

use std::path::PathBuf;
use std::process::{Command, Output};

const AGAT: &str = env!("CARGO_BIN_EXE_agat");
const PASSWORD: &str = "cli-test";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    /// Run agat against this env's home. stdin is closed so nothing can
    /// block on a password prompt.
    fn agat(&self, args: &[&str]) -> Output {
        Command::new(AGAT)
            .arg("--home")
            .arg(self.path("home"))
            .args(args)
            .env("AGAT_VAULT_PASSWORD", PASSWORD)
            .env("NO_COLOR", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    /// Like `agat`, but without the vault password in the environment.
    fn agat_no_password(&self, args: &[&str]) -> Output {
        Command::new(AGAT)
            .arg("--home")
            .arg(self.path("home"))
            .args(args)
            .env_remove("AGAT_VAULT_PASSWORD")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// Ingest + analyze a benign corpus and build self + repertoire.
    fn train(&self) {
        let mut files = Vec::new();
        for i in 0..4u8 {
            let text = format!("benign config file {i}\nkey = value\n").repeat(40 + i as usize);
            files.push(self.write(&format!("benign/text{i}.txt"), text.as_bytes()));
        }
        let mut args = vec!["ingest"];
        let paths: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
        args.extend(paths.iter().map(String::as_str));
        ok(&self.agat(&args));
        ok(&self.agat(&["analyze"]));
        let list = stdout(&self.agat(&["list"]));
        let ids: Vec<&str> = list
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        let mut build = vec!["self", "build"];
        build.extend(ids);
        ok(&self.agat(&build));
        ok(&self.agat(&["repertoire", "generate", "--seed", "1"]));
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn ok(o: &Output) {
    assert!(
        o.status.success(),
        "command failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
        o.status.code(),
        stdout(o),
        stderr(o)
    );
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exited normally")
}

#[test]
fn self_describing_commands_need_no_home() {
    let env = Env::new();
    for args in [
        &["schema"][..],
        &["man"],
        &["completions", "bash"],
        &["--version"],
    ] {
        let o = Command::new(AGAT)
            .arg("--home")
            .arg(env.path("does/not/exist"))
            .args(args)
            .output()
            .unwrap();
        ok(&o);
        assert!(!o.stdout.is_empty(), "{args:?} printed nothing");
    }
}

#[test]
fn scanning_without_a_model_is_a_tool_error_with_a_next_step() {
    let env = Env::new();
    let f = env.write("x.txt", b"hello");
    let o = env.agat_no_password(&["scan", f.to_str().unwrap()]);
    assert_eq!(
        code(&o),
        1,
        "a missing model is an agat error, not a verdict"
    );
    assert!(stderr(&o).contains("repertoire"), "{}", stderr(&o));
}

#[test]
fn stateless_scan_contract() {
    let env = Env::new();
    env.train();
    let samples = env.path("scan");
    env.write("scan/notes.txt", "meeting notes\n".repeat(50).as_bytes());
    env.write(
        "scan/nested/data.bin",
        &(0..4096u32)
            .map(|i| (i * 31 % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let dir = samples.to_str().unwrap();
    let before = stdout(&env.agat(&["list"]));

    // No password, no writes; JSON is an array for a batch, schema-valid.
    let o = env.agat_no_password(&["scan", dir, "--json", "--fail-on", "never"]);
    ok(&o);
    let results: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let results = results.as_array().expect("batch → array");
    assert_eq!(results.len(), 2, "directories are walked recursively");
    let schema: serde_json::Value = serde_json::from_str(&stdout(&env.agat(&["schema"]))).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for r in results {
        assert!(validator.is_valid(r), "invalid result: {r:#}");
        assert_eq!(r["model"]["source"], "local");
    }
    assert_eq!(
        stdout(&env.agat(&["list"])),
        before,
        "a stateless scan writes nothing"
    );

    // The exit code is the worst severity, gated by --fail-on.
    let worst = results
        .iter()
        .map(|r| match r["verdict"]["severity"].as_str().unwrap() {
            "malicious" => 3,
            "review" | "suspicious" => 2,
            _ => 0,
        })
        .max()
        .unwrap();
    assert_eq!(code(&env.agat_no_password(&["scan", dir])), worst);
    assert_eq!(
        code(&env.agat_no_password(&["scan", dir, "--fail-on", "never"])),
        0
    );

    // Parallel and sequential scans agree exactly (bar the timestamp).
    let strip = |o: &Output| -> Vec<serde_json::Value> {
        let mut v: Vec<serde_json::Value> = serde_json::from_slice(&o.stdout).unwrap();
        for r in &mut v {
            r.as_object_mut().unwrap().remove("scanned_at");
        }
        v
    };
    let seq = env.agat_no_password(&["scan", dir, "--json", "-j", "1", "--fail-on", "never"]);
    let par = env.agat_no_password(&["scan", dir, "--json", "-j", "4", "--fail-on", "never"]);
    assert_eq!(strip(&seq), strip(&par));

    // Table and SARIF formats.
    let table =
        stdout(&env.agat_no_password(&["scan", dir, "--output", "table", "--fail-on", "never"]));
    assert!(table.starts_with("SEVERITY"), "{table}");
    assert!(table.contains("2 scanned"), "{table}");
    let sarif: serde_json::Value = serde_json::from_slice(
        &env.agat_no_password(&["scan", dir, "--sarif", "--fail-on", "never"])
            .stdout,
    )
    .unwrap();
    assert_eq!(sarif["version"], "2.1.0");
}

#[test]
fn deny_list_in_config_overrides_the_verdict() {
    let env = Env::new();
    env.train();
    let f = env.write(
        "suspect.txt",
        b"perfectly ordinary text, but on the denylist\n",
    );
    // The sample id in agat's own JSON is the file's SHA-256.
    let first: serde_json::Value = serde_json::from_slice(
        &env.agat_no_password(&["scan", f.to_str().unwrap(), "--json", "--fail-on", "never"])
            .stdout,
    )
    .unwrap();
    assert_ne!(first["verdict"]["severity"], "malicious");
    let sha = first["sample"]["id"].as_str().unwrap().to_string();
    let cfg = env.write(
        "agat.toml",
        format!("[denylist]\nsha256 = [\"{sha}\"]\n").as_bytes(),
    );
    let o = env.agat_no_password(&[
        "--config",
        cfg.to_str().unwrap(),
        "scan",
        f.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code(&o), 3, "denylisted ⇒ malicious ⇒ exit 3");
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["verdict"]["policy"], "denylist");
}

#[test]
fn a_bad_config_fails_fast() {
    let env = Env::new();
    let cfg = env.write("bad.toml", b"[danger]\ndangerous_at = 7\n");
    let o = env.agat_no_password(&["--config", cfg.to_str().unwrap(), "list"]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("dangerous_at"), "{}", stderr(&o));
}

#[test]
fn signed_pack_moves_a_model_between_homes() {
    let a = Env::new();
    a.train();
    let key = a.path("keys/team");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    ok(&a.agat(&["key", "generate", key.to_str().unwrap()]));
    let pack = a.path("model.agatpack");
    let key_secret = format!("{}.key", key.display());
    let key_public = format!("{}.pub", key.display());

    // Unsigned export is refused unless asked for.
    assert_eq!(
        code(&a.agat(&[
            "repertoire",
            "export",
            pack.to_str().unwrap(),
            "--name",
            "t"
        ])),
        1
    );
    ok(&a.agat(&[
        "repertoire",
        "export",
        pack.to_str().unwrap(),
        "--name",
        "team-model",
        "--version",
        "7",
        "--sign",
        &key_secret,
    ]));

    // A fresh home: untrusted signer refused, trusted signer accepted.
    let b = Env::new();
    assert_eq!(
        code(&b.agat(&["repertoire", "import", pack.to_str().unwrap()])),
        1
    );
    ok(&b.agat(&[
        "repertoire",
        "import",
        pack.to_str().unwrap(),
        "--trust",
        &key_public,
    ]));
    let info = stdout(&b.agat(&["repertoire", "info"]));
    assert!(info.contains("pack team-model v7"), "{info}");

    // Both homes give the same verdict, and B names the pack.
    let f = a.write("probe.txt", "probe\n".repeat(30).as_bytes());
    let scan = |e: &Env| -> serde_json::Value {
        serde_json::from_slice(
            &e.agat_no_password(&["scan", f.to_str().unwrap(), "--json", "--fail-on", "never"])
                .stdout,
        )
        .unwrap()
    };
    let (ra, rb) = (scan(&a), scan(&b));
    assert_eq!(ra["verdict"], rb["verdict"]);
    assert_eq!(ra["recognition"], rb["recognition"]);
    assert_eq!(rb["model"]["source"], "pack");
    assert_eq!(rb["model"]["name"], "team-model");

    // A tampered pack is refused.
    let mut text = std::fs::read_to_string(&pack).unwrap();
    text = text.replacen("team-model", "evil-model", 1);
    let tampered = b.write("tampered.agatpack", text.as_bytes());
    let o = b.agat(&[
        "repertoire",
        "import",
        tampered.to_str().unwrap(),
        "--trust",
        &key_public,
    ]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("integrity"), "{}", stderr(&o));
}
