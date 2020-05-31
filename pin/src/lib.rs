// Copyright (C) 2020 Michael Herstine <sp1ff@pobox.com>
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

//! pin -- A command-line client for Pinboard & Instapaper

pub mod error_from;
pub mod instapaper;
pub mod pinboard;
pub mod vars;

use instapaper::Instapaper;
use pinboard::Pinboard;

use serde::Deserialize;
use snafu::{Backtrace, GenerateBacktrace, Snafu};
use strfmt::strfmt;

use std::cmp::max;
use std::collections::HashMap;

////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{}", cause))]
    Other {
        #[snafu(source(true))]
        cause: Box<dyn std::error::Error>,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
}

error_from!(instapaper::Error);
error_from!(pinboard::Error);
error_from!(std::io::Error);

pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                      `pin' Configuration                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// A Target is a pre-defined set of Pinboard tags together with the "read only" flag; i.e. a
/// pre-configured "place" at Pinboard to which a link may be sent
#[derive(Debug, Deserialize)]
pub struct Target {
    pub read_later: bool,
    pub send_to_insty: bool,
    pub tags: Vec<String>,
}

/// Application configuration; by default read from ~/.pin (but that location can be overriden
/// on the command-line), but also assembled from command-line option & the environment.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Pinboard API token
    #[serde(default)]
    pub token: String,
    /// Predefined Pinboard tagsets to apply to links
    #[serde(default)]
    pub targets: HashMap<String, Target>,
    /// Instapaper username
    #[serde(default)]
    pub username: String,
    /// Instapaper password
    #[serde(default)]
    pub password: String,
}

impl Config {
    pub fn new() -> Config {
        Config {
            token: String::from(""),
            targets: HashMap::new(),
            username: String::from(""),
            password: String::from(""),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// Get all Pinboard.in tags & pretty-print 'em
pub fn get_tags<W: std::io::Write, C: pinboard::Pinboard>(
    out: &mut W,
    client: &mut C,
    alpha: bool,
    desc: bool,
    csv: bool,
) -> Result<()> {
    let mut tags = client.get_all_tags()?;
    let max_lens = match csv {
        true => None,
        false => {
            let (mut max_tag, mut max_count) = (0, 0);
            for (tag, count) in &tags {
                if tag.len() > max_tag {
                    max_tag = tag.len();
                }
                if *count > max_count {
                    max_count = *count;
                }
            }
            Some((max_tag, max(9, (max_count as f64).log10() as usize + 1)))
        }
    };
    if alpha {
        tags.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
    } else {
        tags.sort_by(|lhs, rhs| lhs.1.cmp(&rhs.1));
    }
    if desc {
        tags.reverse();
    }

    match max_lens {
        Some((max_tag_len, max_use_count)) => {
            // We're pretty-printing. This is the first time Rust has disappointed me: macros
            // like `format!` and `writeln!` require that the first parameter be a string
            // literal.  This forces me to use some sort of templating crate. The ones at which
            // I glanced seem heavy-weight & aimed at HTML generation. `strfmt', OTOH, seems
            // _too_ basic.

            let rule = format!(
                "+{}+{}+",
                String::from_utf8(vec![b'-'; max_tag_len + 2]).unwrap(),
                String::from_utf8(vec![b'-'; max_use_count + 2]).unwrap()
            );

            let mut fmtvars: HashMap<String, usize> = HashMap::new();
            fmtvars.insert(String::from("1"), max_tag_len);
            fmtvars.insert(String::from("2"), max_use_count);
            let fmt = strfmt("| {{tag:<{1}}} | {{uc:{2}}} |", &fmtvars).unwrap();

            let mut hdrvars: HashMap<String, &str> = HashMap::new();
            hdrvars.insert(String::from("tag"), "Tag");
            hdrvars.insert(String::from("uc"), "Use Count");
            writeln!(out, "{}", strfmt(&fmt, &hdrvars).unwrap())?;

            writeln!(out, "{}", rule)?;

            for tag in &tags {
                let s = format!("{}", tag.1);
                let mut vars: HashMap<String, &str> = HashMap::new();
                vars.insert(String::from("tag"), &tag.0);
                vars.insert(String::from("uc"), &s);
                writeln!(out, "{}", strfmt(&fmt, &vars).unwrap())?;
            }

            writeln!(out, "{}", rule)?;
        }
        None => {
            // We're printing in CSV
            for tag in &tags {
                writeln!(out, "{},{}", tag.0, tag.1)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    struct MockPins {
        tags: std::vec::Vec<(String, usize)>,
    }

    impl MockPins {
        pub fn new(tags: std::vec::Vec<(String, usize)>) -> MockPins {
            MockPins { tags: tags }
        }
    }

    impl crate::pinboard::Pinboard for MockPins {
        fn get_all_tags(&self) -> crate::pinboard::Result<std::vec::Vec<(String, usize)>> {
            Ok(self.tags.clone())
        }
        fn rename_tag(&mut self, old: &str, new: &str) -> crate::pinboard::Result<String> {
            let oldidx = match self.tags.iter().position(|x| x.0 == old) {
                None => return Ok("done".to_owned()),
                Some(oldidx) => oldidx,
            };
            match self.tags.iter().position(|x| x.0 == new) {
                Some(newidx) => {
                    self.tags[newidx].1 += self.tags[oldidx].1;
                    self.tags.remove(oldidx);
                }
                None => self.tags[oldidx].0 = String::from(new),
            }

            return Ok("done".to_owned());
        }
        fn send<I: Iterator<Item = String>>(
            &mut self,
            _url: &str,
            _title: &str,
            _tags: I,
            _rl: bool,
        ) -> crate::pinboard::Result<String> {
            return Ok("done".to_owned());
        }
    }

    #[test]
    fn get_tags_smoke_test_num_asc_pp() {
        let mut buf: Vec<u8> = vec![]; // implements Write
        let mut pins = MockPins::new(vec![(String::from("foo"), 1), (String::from("bar"), 2)]);
        let result = get_tags(&mut buf, &mut pins, false, false, false);

        assert!(result.is_ok());

        let golden = r#"| Tag | Use Count |
+-----+-----------+
| foo |         1 |
| bar |         2 |
+-----+-----------+
"#;
        assert!(golden == std::str::from_utf8(&buf).unwrap());
    }

    #[test]
    fn get_tags_smoke_test_num_asc_csv() {
        let mut buf: Vec<u8> = vec![]; // implements Write
        let mut pins = MockPins::new(vec![(String::from("foo"), 1), (String::from("bar"), 2)]);
        let result = get_tags(&mut buf, &mut pins, false, false, true);

        assert!(result.is_ok());

        let golden = r#"foo,1
bar,2
"#;
        assert!(golden == std::str::from_utf8(&buf).unwrap());
    }

    #[test]
    fn get_tags_smoke_test_num_desc_pp() {
        let mut buf: Vec<u8> = vec![]; // implements Write
        let mut pins = MockPins::new(vec![(String::from("foo"), 1), (String::from("bar"), 2)]);
        let result = get_tags(&mut buf, &mut pins, false, true, false);

        assert!(result.is_ok());

        let golden = r#"| Tag | Use Count |
+-----+-----------+
| bar |         2 |
| foo |         1 |
+-----+-----------+
"#;
        assert!(golden == std::str::from_utf8(&buf).unwrap());
    }

    #[test]
    fn get_tags_smoke_test_num_desc_csv() {
        let mut buf: Vec<u8> = vec![]; // implements Write
        let mut pins = MockPins::new(vec![(String::from("foo"), 1), (String::from("bar"), 2)]);
        let result = get_tags(&mut buf, &mut pins, false, true, true);

        assert!(result.is_ok());

        let golden = r#"bar,2
foo,1
"#;
        assert!(golden == std::str::from_utf8(&buf).unwrap());
    }
} // End module `test'.

/// Rename a tag
pub fn rename_tag<W: std::io::Write>(
    out: &mut W,
    client: &mut pinboard::Client,
    from: &str,
    to: &str,
) -> Result<()> {
    Ok(writeln!(out, "{}", client.rename_tag(from, to)?)?)
}

/// Send a link
pub fn send_link<W: std::io::Write, I: Iterator<Item = String>>(
    _out: &mut W,
    pin_client: &mut pinboard::Client,
    insta_client: Option<&mut instapaper::Client>,
    url: &str,
    title: &str,
    read_later: bool,
    tags: I,
) -> Result<()> {
    pin_client.send(url, title, tags, read_later)?;
    if let Some(cli) = insta_client {
        cli.send(url, Some(title))?;
    }
    Ok(())
}
