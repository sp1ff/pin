//! [`pin`] configuration items.
//!
//! Some runtime options are complex enough that they would be inconvenient to specify on the
//! comnand-line.  Some are likely to be the same across many invocations, and so specifying them
//! once, in a configuration file is more convenient than typing them over & over.

use crate::pinboard::Tag;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

type StdResult<T, E> = std::result::Result<T, E>;

/// A [`Target`] is pre-defined set of Pinboard [`Tag`]s together a few other options applicable to
/// sending links to Pinboard; in other words, a pre-defined "place" at Pinboard to which links may
/// be sent.
///
/// [`Tag`]: pin::pinboard::Tag
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Target {
    read_later: bool,
    send_to_insty: bool,
    tags: Vec<Tag>,
}

impl std::default::Default for Target {
    fn default() -> Self {
        Target {
            read_later: false,
            send_to_insty: false,
            tags: Vec::new(),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(
            f,
            "(Read Later: {}, Instapaper: {}, Tags: {})",
            self.read_later,
            self.send_to_insty,
            match self
                .tags
                .iter()
                .map(|tag| format!("{}", tag))
                .reduce(|accum, item| format!("{}, {}", accum, item))
            {
                Some(s) => String::from(&s[0..12]),
                None => String::from("(none)"),
            }
        )
    }
}

impl Target {
    pub fn get_tags(&self) -> std::slice::Iter<'_, Tag> {
        self.tags.iter()
    }
    pub fn read_later(&self) -> bool {
        self.read_later
    }
}

/// Application configuration
///
/// Generally speaking, I include a version attribute in all my configuration file formats. This
/// allows evolving the file format while still supporting older versions. Regrettably, I release
/// [`pin`] 0.1 without such a field. I added it belatedly in 0.2, using the `default` [serde]
/// attribute to enable older files to still be read (they'll show up as having version 0). This
/// still restricts me to non-breaking changes: i.e. adding optional fields for as long as I want to
/// maintain backward compatibility (usually I use the "internal tagging" [serde] trick to read
/// different versons as distinct types). Ah, well, when & if [`pin`] reaches 1.0 status I can sort
/// it out then.
///
/// [serde]: https://serde.rs/
/// [internal tagging]: https://serde.rs/enum-representations.html#internally-tagged
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    version: u32,
    /// Pinboard API token
    token: Option<String>,
    /// Predefined Pinboard targs for sending links
    targets: Option<HashMap<String, Target>>,
    /// Instapaper username
    #[serde(rename = "username")]
    insty_username: Option<String>,
    /// Instapaper password
    #[serde(rename = "password")]
    insty_password: Option<String>,
}

impl std::default::Default for Config {
    fn default() -> Self {
        Config {
            version: 0,
            token: None,
            targets: None,
            insty_username: None,
            insty_password: None,
        }
    }
}

impl Config {
    pub fn token(&self) -> Option<&String> {
        self.token.as_ref()
    }
    pub fn get_target(&self, name: &str) -> Option<&Target> {
        self.targets.as_ref().and_then(|targets| targets.get(name))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn config_smoke() {
        let s = format!("{}", Target::default());
        assert_eq!(s, "(Read Later: false, Instapaper: false, Tags: (none))");

        let _cfg: Config = toml::from_str(
            "username = \"jdoe@hotmail.com\"
[targets]
[targets.1]
tags = [\"@review\", \"news\"]
read_later = true
send_to_insty = true
",
        )
        .unwrap();
    }
}
