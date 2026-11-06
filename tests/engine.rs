//! The security properties of the decision layer. The models here are synthetic
//! on purpose: the invariants must hold for any model, including a wrong one.

use trustauto::engine::{decide, Scorer, Verdict};
use trustauto::policy::{Mode, Policy};
use trustauto::request::{Context, Request};
use trustauto::transformer::Score;

const SAMPLE: &str = include_str!("../config/policy.toml");

fn sample(mode: Mode) -> Policy {
    let mut p = Policy::parse(SAMPLE).expect("sample policy must be valid");
    p.mode = mode;
    p
}

/// The sample policy without the network check, to see the model's part alone.
fn offline(mode: Mode) -> Policy {
    let mut p = sample(mode);
    p.network.ask = false;
    p
}

fn req(bin: &str, args: &[&str]) -> Request {
    Request {
        bin: bin.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        ctx: Context::quiet(),
    }
}

/// As the front end sends it: symlinks in the binary's path resolved, like the
/// policy's own paths. On Ubuntu 26.04, /usr/sbin/ip is a link to /usr/bin/ip.
fn resolved(bin: &str, args: &[&str]) -> Request {
    let real = std::fs::canonicalize(bin).map_or_else(|_| bin.to_string(), |p| p.to_string_lossy().into_owned());
    req(&real, args)
}

/// A constant-output model: every command scores the same.
struct Fixed {
    risk: f32,
    known: bool,
}

impl Scorer for Fixed {
    fn score(&self, _: &Request) -> Score {
        Score { risk: self.risk, known: self.known }
    }

    fn threshold(&self) -> f32 {
        0.1
    }
}

const CERTAIN_SAFE: Fixed = Fixed { risk: 0.0, known: true };
const CERTAIN_RISKY: Fixed = Fixed { risk: 1.0, known: true };
const SAFE_BUT_UNKNOWN: Fixed = Fixed { risk: 0.0, known: false };
const BROKEN: Fixed = Fixed { risk: f32::NAN, known: true };

fn verdict(policy: &Policy, model: Option<&Fixed>, r: &Request) -> Verdict {
    decide(policy, model.map(|m| m as &dyn Scorer), r).verdict
}

#[test]
fn a_model_that_trusts_everything_stays_inside_the_ceiling() {
    let attacks: &[(&str, &[&str])] = &[
        ("/usr/bin/bash", &["-c", "id"]),
        ("/usr/bin/python3", &["-c", "import os"]),
        ("/usr/bin/apt-get", &["-o", "APT::Update::Pre-Invoke::=/bin/sh", "update"]),
        ("/usr/bin/apt", &["-o", "APT::Update::Pre-Invoke::=/bin/sh", "update"]),
        ("/usr/bin/apt", &["install", "./evil.deb"]),
        ("/usr/bin/apt", &["install", "foo=1.0"]),
        ("/usr/bin/apt", &["install", "--allow-unauthenticated", "foo"]),
        ("/usr/bin/apt", &["remove", "linux."]),
        ("/usr/bin/apt", &["install", "foo-"]),
        ("/usr/bin/systemctl", &["edit", "ssh"]),
        ("/usr/bin/systemctl", &["restart", "*"]),
        ("/usr/bin/systemctl", &["restart", "--force", "ssh"]),
        ("/usr/bin/journalctl", &["-u", "ssh", "--no-pager", "-o", "x"]),
        ("/usr/bin/find", &["/", "-exec", "sh", ";"]),
        ("/usr/local/bin/unknown", &[]),
    ];
    let policy = offline(Mode::Hybrid);
    for (bin, args) in attacks {
        let r = req(bin, args);
        assert_ne!(verdict(&policy, Some(&CERTAIN_SAFE), &r), Verdict::Allow, "{r:?}");
    }
}

#[test]
fn ml_only_never_elevates_what_it_cannot_see_even_when_told_to_judge_everything() {
    let mut policy = offline(Mode::Ml);
    policy.ml.judge_unknown = true;
    let attacks: &[(&str, &[&str])] = &[
        ("/usr/bin/bash", &["-c", "id"]),
        ("/usr/bin/python3", &["/root/x.py"]),
        ("/usr/bin/vim", &["/etc/hosts"]),
        ("/usr/bin/systemctl", &["edit", "ssh"]),
        ("/usr/bin/apt-get", &["-o", "APT::Update::Pre-Invoke::=/bin/sh", "update"]),
        ("/usr/bin/find", &["/", "-exec", "sh", ";"]),
        ("/usr/sbin/mkfs.ext4", &["/dev/sda1"]),
        ("/usr/bin/mount", &["/dev/sdb1", "/mnt"]),
        ("/usr/sbin/modprobe", &["evil"]),
        ("/usr/bin/curl", &["-o", "/usr/local/bin/x", "https://example.com/x"]),
        ("/usr/bin/chmod", &["4755", "/etc/shadow"]),
        ("/usr/bin/tool", &["a;id"]),
        ("/usr/sbin/vipw", &[]),
    ];
    for (bin, args) in attacks {
        let r = req(bin, args);
        assert_ne!(verdict(&policy, Some(&CERTAIN_SAFE), &r), Verdict::Allow, "{r:?}");
    }
}

#[test]
fn ml_only_lets_the_model_decide_commands_without_rules() {
    let policy = offline(Mode::Ml);
    let r = req("/usr/sbin/useradd", &["ta-new"]);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &r), Verdict::Allow);
    assert_eq!(verdict(&policy, Some(&CERTAIN_RISKY), &r), Verdict::Ask);
    let restart = req("/usr/bin/systemctl", &["restart", "nginx"]);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &restart), Verdict::Allow);
}

#[test]
fn ml_only_asks_about_unknown_programs_unless_the_operator_chose_otherwise() {
    let mut policy = offline(Mode::Ml);
    let r = req("/usr/sbin/rare-admin-tool", &["--apply"]);
    assert_eq!(verdict(&policy, Some(&SAFE_BUT_UNKNOWN), &r), Verdict::Ask);
    policy.ml.judge_unknown = true;
    assert_eq!(verdict(&policy, Some(&SAFE_BUT_UNKNOWN), &r), Verdict::Allow);
}

#[test]
fn ml_only_keeps_deny_ask_and_user_rules() {
    let text = r#"
        version = 1
        mode = "ml"
        [network]
        ask = false
        [[rule]]
        id = "no"
        action = "deny"
        bin = "/usr/sbin/useradd"
        args = ["{any}*"]
        [[rule]]
        id = "approve"
        action = "ask"
        bin = "/usr/bin/systemctl"
        args = ["{any}*"]
        [[rule]]
        id = "plain"
        action = "user"
        bin = "/usr/sbin/ip"
        args = ["{any}*"]
    "#;
    let policy = Policy::parse(text).unwrap();
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &resolved("/usr/sbin/useradd", &["x"])), Verdict::Deny);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &resolved("/usr/bin/systemctl", &["restart", "x"])), Verdict::Ask);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &resolved("/usr/sbin/ip", &["addr"])), Verdict::User);
}

#[test]
fn ml_only_runs_the_callers_own_work_without_root() {
    let file = std::env::temp_dir().join(format!("ta-own-{}", std::process::id()));
    std::fs::write(&file, "x").unwrap();
    let r = req("/usr/bin/cat", &[file.to_str().unwrap()]);
    assert_eq!(verdict(&offline(Mode::Ml), Some(&CERTAIN_SAFE), &r), Verdict::User);
    assert_eq!(verdict(&offline(Mode::Ml), None, &r), Verdict::User);
    std::fs::remove_file(&file).unwrap();
}

#[test]
fn ml_can_elevate_only_inside_an_envelope_in_hybrid_mode() {
    let policy = offline(Mode::Hybrid);
    let r = req("/usr/bin/apt", &["install", "htop"]);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &r), Verdict::Allow);
    assert_eq!(verdict(&policy, Some(&CERTAIN_RISKY), &r), Verdict::Ask);
    assert_eq!(verdict(&policy, Some(&SAFE_BUT_UNKNOWN), &r), Verdict::Ask);
}

#[test]
fn network_commands_ask_by_default_in_every_mode() {
    let update = req("/usr/bin/apt", &["update"]);
    let install = req("/usr/bin/apt", &["install", "htop"]);
    for mode in [Mode::Rule, Mode::Hybrid, Mode::Ml] {
        let policy = sample(mode);
        assert!(policy.network.ask);
        assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &update), Verdict::Ask, "{mode:?}");
        assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &install), Verdict::Ask, "{mode:?}");
    }
    let d = decide(&sample(Mode::Rule), None, &update);
    assert!(d.reasons.iter().any(|r| r.contains("network")), "{:?}", d.reasons);
}

#[test]
fn rule_mode_ignores_the_model_and_does_not_elevate_envelopes() {
    let policy = offline(Mode::Rule);
    let update = req("/usr/bin/apt", &["update"]);
    assert_eq!(verdict(&policy, None, &update), Verdict::Allow);
    assert_eq!(verdict(&policy, Some(&CERTAIN_RISKY), &update), Verdict::Allow);
    let install = req("/usr/bin/apt", &["install", "htop"]);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &install), Verdict::Ask);
}

#[test]
fn hybrid_model_can_veto_an_allow_rule() {
    let policy = offline(Mode::Hybrid);
    let r = req("/usr/bin/apt", &["update"]);
    assert_eq!(verdict(&policy, Some(&CERTAIN_SAFE), &r), Verdict::Allow);
    assert_eq!(verdict(&policy, Some(&CERTAIN_RISKY), &r), Verdict::Ask);
}

#[test]
fn missing_or_broken_model_fails_closed() {
    let update = req("/usr/bin/apt", &["update"]);
    let install = req("/usr/bin/apt", &["install", "htop"]);
    let admin = req("/usr/sbin/useradd", &["x"]);
    for mode in [Mode::Ml, Mode::Hybrid] {
        let policy = offline(mode);
        for r in [&update, &install, &admin] {
            assert_ne!(verdict(&policy, None, r), Verdict::Allow, "{mode:?} {r:?}");
            assert_ne!(verdict(&policy, Some(&BROKEN), r), Verdict::Allow, "{mode:?} {r:?}");
        }
    }
}

#[test]
fn operator_cap_can_only_tighten_the_threshold() {
    let mut policy = offline(Mode::Hybrid);
    let r = req("/usr/bin/apt", &["install", "htop"]);
    let borderline = Fixed { risk: 0.05, known: true };
    assert_eq!(verdict(&policy, Some(&borderline), &r), Verdict::Allow);
    policy.ml.low = Some(0.01);
    assert_eq!(verdict(&policy, Some(&borderline), &r), Verdict::Ask);
    policy.ml.low = Some(0.5);
    let above = Fixed { risk: 0.2, known: true };
    assert_eq!(verdict(&policy, Some(&above), &r), Verdict::Ask, "a looser cap must not widen the model's threshold");
}

#[test]
fn deny_beats_everything_in_any_order() {
    let text = r#"
        version = 1
        mode = "rule"
        [[rule]]
        id = "ok"
        action = "allow"
        bin = "/usr/bin/tool"
        args = []
        [[rule]]
        id = "no"
        action = "deny"
        bin = "/usr/bin/tool"
        args = ["{any}*"]
        [[rule]]
        id = "later"
        action = "ask"
        bin = "/usr/bin/tool"
        args = []
    "#;
    let policy = Policy::parse(text).unwrap();
    let d = decide(&policy, None, &req("/usr/bin/tool", &[]));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule.as_deref(), Some("no"));
}

#[test]
fn precedence_runs_ask_allow_envelope_user() {
    let build = |actions: &[&str]| {
        let mut text = String::from("version = 1\nmode = \"rule\"\n");
        for (i, action) in actions.iter().enumerate() {
            text.push_str(&format!(
                "[[rule]]\nid = \"r{i}\"\naction = \"{action}\"\nbin = \"/usr/bin/tool\"\nargs = []\n"
            ));
        }
        Policy::parse(&text).unwrap()
    };
    let r = req("/usr/bin/tool", &[]);
    assert_eq!(verdict(&build(&["allow", "ask"]), None, &r), Verdict::Ask);
    assert_eq!(verdict(&build(&["user", "allow"]), None, &r), Verdict::Allow);
    assert_eq!(verdict(&build(&["user", "envelope"]), None, &r), Verdict::Ask);
    assert_eq!(verdict(&build(&["user"]), None, &r), Verdict::User);
}

#[test]
fn unknown_commands_need_an_approver_in_rule_and_hybrid_mode() {
    for mode in [Mode::Rule, Mode::Hybrid] {
        let r = req("/usr/bin/never-heard-of-it", &["x"]);
        assert_eq!(verdict(&sample(mode), Some(&CERTAIN_SAFE), &r), Verdict::Ask, "{mode:?}");
    }
}

#[test]
fn no_terminal_blocks_automatic_elevation() {
    let mut r = req("/usr/bin/apt", &["update"]);
    r.ctx.has_tty = false;
    let mut policy = offline(Mode::Rule);
    assert_eq!(verdict(&policy, None, &r), Verdict::Ask);
    policy.require_tty = false;
    assert_eq!(verdict(&policy, None, &r), Verdict::Allow);
}

#[test]
fn hard_guard_overrides_a_careless_rule() {
    let text = r#"
        version = 1
        mode = "rule"
        [[rule]]
        id = "careless"
        action = "allow"
        bin = "/usr/bin/tool"
        args = ["/etc/shadow"]
    "#;
    let policy = Policy::parse(text).unwrap();
    let d = decide(&policy, None, &req("/usr/bin/tool", &["/etc/shadow"]));
    assert_eq!(d.verdict, Verdict::Ask);
    assert!(d.reasons.iter().any(|r| r.contains("sensitive")));
}

// --- Policy validation -------------------------------------------------------

fn rule_policy(action: &str, bin: &str, args: &str) -> Result<Policy, String> {
    Policy::parse(&format!(
        "version = 1\nmode = \"rule\"\n[[rule]]\nid = \"r\"\naction = \"{action}\"\nbin = \"{bin}\"\nargs = {args}\n"
    ))
}

#[test]
fn policy_refuses_auto_elevating_shell_equivalents() {
    for bin in ["/usr/bin/bash", "/bin/sh", "/usr/bin/python3.12", "/usr/bin/vim", "/usr/bin/find",
                "/usr/bin/env", "/usr/bin/sudo", "/usr/bin/docker", "/usr/bin/tee", "/usr/bin/git"] {
        for action in ["allow", "envelope"] {
            assert!(rule_policy(action, bin, "[]").is_err(), "{action} {bin}");
        }
        assert!(rule_policy("ask", bin, "[]").is_ok(), "{bin}");
        assert!(rule_policy("deny", bin, "[]").is_ok(), "{bin}");
    }
}

#[test]
fn policy_refuses_any_in_elevating_rules() {
    for action in ["allow", "envelope"] {
        assert!(rule_policy(action, "/usr/bin/tool", r#"["{any}"]"#).is_err());
        assert!(rule_policy(action, "/usr/bin/tool", r#"["{any}*"]"#).is_err());
    }
    for action in ["deny", "ask", "user"] {
        assert!(rule_policy(action, "/usr/bin/tool", r#"["{any}*"]"#).is_ok());
    }
}

#[test]
fn policy_rejects_malformed_input() {
    let cases = [
        "".to_string(),
        "version = 2\nmode = \"rule\"\n".to_string(),
        "version = 1\nmode = \"magic\"\n".to_string(),
        "version = 1\nmode = \"rule\"\nsurprise = true\n".to_string(),
        "version = 1\nmode = \"rule\"\n[ml]\nlow = 0.9\nhigh = 0.1\n".to_string(),
        "version = 1\nmode = \"rule\"\n[ml]\nlow = -1.0\nhigh = 0.1\n".to_string(),
        "version = 1\nmode = \"rule\"\n[ml]\nlow = nan\nhigh = 0.1\n".to_string(),
        "version = 1\nmode = \"rule\"\n[network]\nask = \"yes\"\n".to_string(),
        "version = 1\nmode = \"rule\"\n[ml]\njudge_unknown = 1\n".to_string(),
        "version = 1\nmode = \"rule\"\n[approval]\nattempts = 0\n".to_string(),
        "version = 1\nmode = \"rule\"\n[[rule]]\nid = \"a\"\naction = \"allow\"\nbin = \"/x\"\nargs = []\n[[rule]]\nid = \"a\"\naction = \"allow\"\nbin = \"/y\"\nargs = []\n".to_string(),
    ];
    for text in cases {
        assert!(Policy::parse(&text).is_err(), "{text}");
    }
    assert!(rule_policy("allow", "tool", "[]").is_err());
    assert!(rule_policy("allow", "/usr/../bin/tool", "[]").is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{nope}"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{word}+", "x"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["x{word}"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{opt:}"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{path:/}"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{path:/tmp}"]"#).is_err());
    assert!(rule_policy("allow", "/usr/bin/tool", r#"["{path:/etc/}"]"#).is_err());
}

// --- Typed patterns ----------------------------------------------------------

fn accepts(pattern: &str, arg: &str) -> bool {
    let policy = rule_policy("allow", "/usr/bin/tool", &format!(r#"["{pattern}"]"#)).unwrap();
    policy.rules[0].matches(&req("/usr/bin/tool", &[arg]))
}

#[test]
fn package_pattern_blocks_apt_special_syntax() {
    for ok in ["htop", "g++", "libc6", "python3-pip"] {
        assert!(accepts("{pkg}", ok), "{ok}");
    }
    for bad in ["", "-o", "--yes", "./evil.deb", "/tmp/evil.deb", "foo=1.0", "foo/stable",
                "foo-", "lib.", "foo*", "Foo", "foo bar", "foo\n", "foo:arm64", "日本語"] {
        assert!(!accepts("{pkg}", bad), "{bad:?}");
    }
}

#[test]
fn unit_pattern_blocks_options_and_globs() {
    for ok in ["nginx", "nginx.service", "getty@tty1.service", "dev-sda1.device"] {
        assert!(accepts("{unit}", ok), "{ok}");
    }
    for bad in ["", "-f", "--force", "*", "ng?nx", "[a]", "a b", "a/b", "$(id)"] {
        assert!(!accepts("{unit}", bad), "{bad:?}");
    }
}

#[test]
fn word_and_int_patterns() {
    assert!(accepts("{word}", "a.b:c@d+e-f_1"));
    for bad in ["-x", ".hidden", "a b", "a/b", "a;b", ""] {
        assert!(!accepts("{word}", bad), "{bad:?}");
    }
    assert!(accepts("{int}", "123"));
    for bad in ["", "-1", "1.5", "0x10", "1234567890123456789"] {
        assert!(!accepts("{int}", bad), "{bad:?}");
    }
}

#[test]
fn repeat_counts_are_enforced() {
    let plus = rule_policy("allow", "/usr/bin/tool", r#"["install", "{pkg}+"]"#).unwrap();
    let rule = &plus.rules[0];
    assert!(!rule.matches(&req("/usr/bin/tool", &["install"])));
    assert!(rule.matches(&req("/usr/bin/tool", &["install", "a"])));
    assert!(rule.matches(&req("/usr/bin/tool", &["install", "a", "b"])));
    assert!(!rule.matches(&req("/usr/bin/tool", &["install", "a", "-y"])));

    let star = rule_policy("allow", "/usr/bin/tool", r#"["x", "{pkg}*"]"#).unwrap();
    assert!(star.rules[0].matches(&req("/usr/bin/tool", &["x"])));

    let exact = rule_policy("allow", "/usr/bin/tool", r#"["x"]"#).unwrap();
    assert!(!exact.rules[0].matches(&req("/usr/bin/tool", &["x", "y"])));
    assert!(!exact.rules[0].matches(&req("/usr/bin/tool", &[])));
}

#[test]
fn path_pattern_resolves_symlinks_and_rejects_traversal() {
    let base = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("ta-engine-{}", std::process::id()));
    let inside = base.join("logs");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(inside.join("app.log"), "").unwrap();
    std::fs::write(base.join("secret"), "").unwrap();
    std::os::unix::fs::symlink(base.join("secret"), inside.join("escape")).unwrap();

    let prefix = inside.to_str().unwrap();
    let policy = rule_policy("allow", "/usr/bin/tool", &format!(r#"["{{path:{prefix}}}"]"#)).unwrap();
    let rule = &policy.rules[0];
    let check = |arg: String| rule.matches(&req("/usr/bin/tool", &[arg.as_str()]));

    assert!(check(format!("{prefix}/app.log")));
    assert!(!check(format!("{prefix}/escape")), "symlink out of the prefix");
    assert!(!check(format!("{prefix}/../secret")), "traversal");
    assert!(!check(format!("{prefix}//app.log")), "doubled slash");
    assert!(!check(format!("{prefix}/missing")), "must exist");
    assert!(!check(format!("{prefix}x/app.log")), "sibling sharing the prefix");
    assert!(!check(prefix.to_string()), "the prefix itself");
    assert!(!check("app.log".to_string()), "relative");

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn wrappers_cover_elevating_rules_but_not_deny_rules() {
    let names = sample(Mode::Rule).wrapper_names();
    assert!(names.contains(&"apt".to_string()));
    assert!(names.contains(&"systemctl".to_string()));
    assert!(!names.contains(&"rm".to_string()));
    assert!(!names.contains(&"bash".to_string()));
}
