//! The character, a block cursor with eyes, shown only on a terminal. The front
//! end shows its own prediction for decisions the rules settle; for decisions that
//! need the model, which only the broker loads, the broker shows its verdict.
//! Nothing depends on a face: the broker decides again and has the last word.

use crate::engine::{Decision, Verdict};
use crate::request::escape_display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    Root,
    User,
    Ask,
    Deny,
    Awake,
    Asleep,
}

impl Face {
    pub fn of(verdict: Verdict) -> Face {
        match verdict {
            Verdict::Allow => Face::Root,
            Verdict::User => Face::User,
            Verdict::Ask => Face::Ask,
            Verdict::Deny => Face::Deny,
        }
    }

    fn eyes(self) -> &'static str {
        match self {
            Face::Root => "^ ^",
            Face::User | Face::Awake => "0 0",
            Face::Ask => "? ?",
            Face::Deny => "> <",
            Face::Asleep => "- -",
        }
    }

    /// 256-colour background, close to the verdict colours of the website.
    fn colour(self) -> u8 {
        match self {
            Face::Root => 215,
            Face::User | Face::Awake => 115,
            Face::Ask => 147,
            Face::Deny => 210,
            Face::Asleep => 245,
        }
    }
}

/// How a face may be drawn on a given stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Hidden,
    Plain,
    Colour,
}

/// Decides from the stream and the environment. Never reads a terminal's reply.
pub fn style(is_terminal: bool, face_setting: Option<&str>, no_colour: bool, term: Option<&str>) -> Style {
    if !is_terminal || face_setting == Some("off") {
        return Style::Hidden;
    }
    if no_colour || matches!(term, None | Some("") | Some("dumb")) {
        return Style::Plain;
    }
    Style::Colour
}

pub fn draw(face: Face, style: Style) -> String {
    match style {
        Style::Hidden => String::new(),
        Style::Plain => format!("[{}]", face.eyes()),
        Style::Colour => format!("\x1b[38;5;16;48;5;{}m {} \x1b[0m", face.colour(), face.eyes()),
    }
}

/// The line before an elevated, approved or refused command. A `user` verdict
/// gets none, since nothing about the command changes.
pub fn announcement(decision: &Decision, style: Style) -> Option<String> {
    let word = match decision.verdict {
        Verdict::Allow => "root",
        Verdict::Ask => "needs approval",
        Verdict::Deny => "refused",
        Verdict::User => return None,
    };
    if style == Style::Hidden {
        return None;
    }
    let face = draw(Face::of(decision.verdict), style);
    Some(match decision.rule.as_deref() {
        Some(rule) => format!("{face} {word} ({})", escape_display(rule)),
        None => format!("{face} {word}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_verdict_has_its_own_eyes() {
        assert_eq!(draw(Face::of(Verdict::Allow), Style::Plain), "[^ ^]");
        assert_eq!(draw(Face::of(Verdict::User), Style::Plain), "[0 0]");
        assert_eq!(draw(Face::of(Verdict::Ask), Style::Plain), "[? ?]");
        assert_eq!(draw(Face::of(Verdict::Deny), Style::Plain), "[> <]");
    }

    #[test]
    fn pipes_and_the_off_setting_show_nothing() {
        assert_eq!(style(false, None, false, Some("xterm")), Style::Hidden);
        assert_eq!(style(true, Some("off"), false, Some("xterm")), Style::Hidden);
        assert_eq!(draw(Face::Root, Style::Hidden), "");
    }

    #[test]
    fn colour_needs_a_capable_terminal() {
        assert_eq!(style(true, None, false, Some("xterm-256color")), Style::Colour);
        assert_eq!(style(true, None, true, Some("xterm-256color")), Style::Plain);
        assert_eq!(style(true, None, false, Some("dumb")), Style::Plain);
        assert_eq!(style(true, None, false, None), Style::Plain);
    }

    #[test]
    fn colour_resets_afterwards() {
        assert!(draw(Face::Deny, Style::Colour).ends_with("\x1b[0m"));
    }
}
