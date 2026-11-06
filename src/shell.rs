//! Shell integration. Wrappers are ordinary functions, so the shell has already
//! done its parsing and expansion by the time TrustAuto sees the exact argv.
//! Pipelines, redirections and quoting behave as usual, and rewriting a command
//! line (which could disagree with the shell about its meaning) is never needed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
}

impl Shell {
    pub fn from_name(s: &str) -> Option<Shell> {
        match s {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            _ => None,
        }
    }
}

/// Names that are safe to paste into shell source.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
        && !name.starts_with('-')
}

const BASH_HOOK: &str = r#"  if [ -z "${__TRUSTAUTO_INIT:-}" ]; then
    __TRUSTAUTO_INIT=1
    if declare -F command_not_found_handle >/dev/null; then
      eval "__trustauto_orig_cnf() $(declare -f command_not_found_handle | tail -n +2)"
    fi
    command_not_found_handle() {
      if command trustauto known "$1" 2>/dev/null; then
        command trustauto run -- "$@"
        return $?
      fi
      if declare -F __trustauto_orig_cnf >/dev/null; then
        __trustauto_orig_cnf "$@"
        return $?
      fi
      printf 'bash: %s: command not found\n' "$1" >&2
      return 127
    }
  fi
"#;

const ZSH_HOOK: &str = r#"  if [ -z "${__TRUSTAUTO_INIT:-}" ]; then
    __TRUSTAUTO_INIT=1
    if (( ${+functions[command_not_found_handler]} )); then
      functions[__trustauto_orig_cnf]=$functions[command_not_found_handler]
    fi
    command_not_found_handler() {
      if command trustauto known "$1" 2>/dev/null; then
        command trustauto run -- "$@"
        return $?
      fi
      if (( ${+functions[__trustauto_orig_cnf]} )); then
        __trustauto_orig_cnf "$@"
        return $?
      fi
      printf 'zsh: command not found: %s\n' "$1" >&2
      return 127
    }
  fi
"#;

/// Produces the script for `eval "$(trustauto shell-init bash)"`. Only
/// interactive shells change, so existing scripts keep their exact behaviour.
pub fn init_script(shell: Shell, names: &[String]) -> String {
    let mut out = String::from("# TrustAuto shell integration\ncase $- in *i*)\n");
    for name in names.iter().filter(|n| safe_name(n)) {
        out.push_str(&format!("  unalias {name} 2>/dev/null\n"));
        out.push_str(&format!(
            "  function {name} {{ command trustauto run -- {name} \"$@\"; }}\n"
        ));
    }
    out.push_str(match shell {
        Shell::Bash => BASH_HOOK,
        Shell::Zsh => ZSH_HOOK,
    });
    out.push_str(";; esac\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_pass_exact_arguments() {
        let script = init_script(Shell::Bash, &["apt".to_string()]);
        assert!(script.contains("function apt { command trustauto run -- apt \"$@\"; }"));
        assert!(script.starts_with("# TrustAuto"));
        assert!(script.contains("case $- in *i*)"));
    }

    #[test]
    fn hostile_names_never_reach_the_script() {
        let names = vec![
            "a;rm -rf /".to_string(),
            "$(id)".to_string(),
            "-x".to_string(),
            "ok.name+1".to_string(),
        ];
        let script = init_script(Shell::Zsh, &names);
        assert!(!script.contains("rm -rf"));
        assert!(!script.contains("$(id)"));
        assert!(!script.contains("function -x"));
        assert!(script.contains("function ok.name+1 "));
    }

    #[test]
    fn each_shell_gets_its_own_hook() {
        assert!(init_script(Shell::Bash, &[]).contains("command_not_found_handle()"));
        assert!(init_script(Shell::Zsh, &[]).contains("command_not_found_handler()"));
    }
}
