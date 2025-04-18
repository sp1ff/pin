// Copyright (C) 2020-2025 Michael Herstine <sp1ff@pobox.com>
//
// This file is part of pin.
//
// pin is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// pin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
// Public License for more details.
//
// You should have received a copy of the GNU General Public License along with pin.  If not, see
// <http://www.gnu.org/licenses/>.

//! `pin` configuration items.
//!
//! Some runtime options are complex enough that they would be inconvenient to specify on the
//! comnand-line.  Some are likely to be the same across many invocations, and so specifying them
//! once, in a configuration file is more convenient than typing them over & over.

use crate::pinboard::Tag;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

type StdResult<T, E> = std::result::Result<T, E>;

/// A [Target] is pre-defined set of Pinboard [Tag]s together a few other options applicable to
/// sending links to Pinboard; in other words, a pre-defined "place" at Pinboard to which links may
/// be sent.
///
/// [Tag]: crate::pinboard::Tag
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Target {
    read_later: bool,
    send_to_insty: bool,
    tags: Vec<Tag>,
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
/// allows evolving the file format while still supporting older versions. Regrettably, I released
/// `pin` 0.1 without such a field. I added it belatedly in 0.2, using the `default` [serde]
/// attribute to enable older files to still be read (they'll show up as having version 0). This
/// still restricts me to non-breaking changes: i.e. adding optional fields for as long as I want to
/// maintain backward compatibility (usually I use the "internal tagging" [serde] trick to read
/// different versons as distinct types). Ah, well, when & if `pin` reaches 1.0 status I can sort it
/// out then.
///
/// [serde]: https://serde.rs/
/// [internal tagging]: https://serde.rs/enum-representations.html#internally-tagged
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
