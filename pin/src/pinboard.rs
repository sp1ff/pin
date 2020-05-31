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

//! pinboard -- pinboard API client
//!
//! This module provides a rudimentary client for the [Pinboard](https://pinboard.in/)
//! [API](https://pinboard.in/api/).

use crate::error_from;
use crate::vars::PIN_UA;

use boolinator::Boolinator;
use json::JsonValue;
use log::debug;
use reqwest::header::USER_AGENT;
use serde_urlencoded::to_string as encode;
use snafu::{Backtrace, GenerateBacktrace, OptionExt, Snafu};

use std::vec::Vec;

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                       module Error type                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Snafu)]
pub enum Error {
    /// Allow conversion from another Error to this module's error type by wrapping the original
    /// (with a backtrace)
    #[snafu(display("{}", cause))]
    Other {
        #[snafu(source(true))]
        cause: Box<dyn std::error::Error>,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
    /// Failed HTTP call (i.e. non-2XX status code returned from the API)
    #[snafu(display("While calling `{}' got {}", ep, status))]
    Http {
        ep: String,
        status: reqwest::StatusCode,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
    #[snafu(display("Got unexpected JSON type {:#?} for field `{}'", item, name))]
    BadJsonFieldType { name: String, item: JsonValue },
    #[snafu(display("Unexpected JSON type {:#?}", item))]
    BadJsonType {
        item: JsonValue,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
}

error_from!(json::Error);
error_from!(std::num::ParseIntError);
error_from!(reqwest::Error);
error_from!(serde_urlencoded::ser::Error);

pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////////////////////////////////

/// Break down the JSON respones body (to /v1/tags/get) into a Vec of (String, usize) tuples
/// (representing tag name & use count, respectively).
pub fn counts_for_json(text: &str) -> Result<Vec<(String, usize)>> {
    let val = json::parse(text)?;
    match val {
        JsonValue::Object(doc) => doc
            .iter()
            .map(|(name, value)| match value {
                JsonValue::Short(s) => Ok((name.to_string(), s.as_str().parse::<usize>()?)),
                _ => Err(Error::BadJsonFieldType {
                    name: name.to_string(),
                    item: value.clone(),
                }),
            })
            .collect(),
        _ => Err(Error::BadJsonType {
            item: val,
            back: Backtrace::generate(),
        }),
    }
}

#[cfg(test)]
mod json_tests {
    use super::*;
    /// Run a few basic tests of JSON parsing
    #[test]
    fn json_smoke() {
        let x = counts_for_json("{\"@gdrive\":\"1\",\"@review-c++\":\"56\"}");
        if let Ok(y) = x {
            assert_eq!(
                y,
                vec![("@gdrive".to_string(), 1), ("@review-c++".to_string(), 56)]
            );
        }
    }
}

pub trait Pinboard {
    /// Retrieve your Pinboard tags along with their use counts
    fn get_all_tags(&self) -> Result<Vec<(String, usize)>>;
    /// Rename tag "from" to "to"
    fn rename_tag(&mut self, from: &str, to: &str) -> Result<String>;
    /// Send a single link to Pinboard
    fn send<I: Iterator<Item = String>>(
        &mut self,
        url: &str,
        title: &str,
        tags: I,
        read_later: bool,
    ) -> Result<String>;
}

/// Pinboard API client; construct with your API token.
pub struct Client {
    token: String,
}

impl Client {
    pub fn new(token: String) -> Client {
        Client { token: token }
    }
}

impl Pinboard for Client {
    fn get_all_tags(&self) -> Result<Vec<(String, usize)>> {
        let ep = "/v1/tags/get";
        let req = format!(
            "https://api.pinboard.in{}?auth_token={}&format=json",
            ep, self.token
        );

        debug!("requesting {}...", req);
        let client = reqwest::blocking::Client::new();
        let rsp = client.get(&req).header(USER_AGENT, PIN_UA).send()?;

        (rsp.status() == reqwest::StatusCode::OK)
            .as_option()
            .context(Http {
                ep: String::from(ep),
                status: rsp.status(),
            })?;

        let rsp = rsp.text()?;
        debug!("requesting {}...done: {}", req, rsp);

        counts_for_json(&rsp)
    } // End function `get_all_tags'.

    fn rename_tag(&mut self, from: &str, to: &str) -> Result<String> {
        let ep = "/v1/tags/rename";
        let req = format!(
            "https://api.pinboard.in{}?auth_token={}&{}",
            ep,
            self.token,
            encode(&[("old", from), ("new", to), ("format", "json")])?
        );

        debug!("requesting {}...", req);
        let client = reqwest::blocking::Client::new();
        let rsp = client.get(&req).header(USER_AGENT, PIN_UA).send()?;
        (rsp.status() == reqwest::StatusCode::OK)
            .as_option()
            .context(Http {
                ep: String::from(ep),
                status: rsp.status(),
            })?;

        let rsp = rsp.text()?;
        debug!("requesting {}...done: {}", req, rsp);

        let val = json::parse(&rsp)?;
        match val {
            json::JsonValue::Object(obj) => Ok(obj["result"].to_string()),
            _ => Err(Error::BadJsonType {
                item: val,
                back: Backtrace::generate(),
            }),
        }
    }

    fn send<I: Iterator<Item = String>>(
        &mut self,
        url: &str,
        title: &str,
        tags: I,
        rl: bool,
    ) -> Result<String> {
        let ep = "/v1/posts/add";
        let args = &[
            ("url", url),
            ("description", title),
            (
                "tags",
                &tags.fold(String::from(""), |mut acc, x| {
                    acc.push(' ');
                    acc.push_str(&x);
                    acc
                }),
            ),
            (
                "toread",
                match rl {
                    true => "yes",
                    false => "no",
                },
            ),
        ];
        let enc_url = serde_urlencoded::to_string(args)?;
        let req = format!(
            "https://api.pinboard.in{}?auth_token={}&format=json&{}",
            ep, self.token, enc_url
        );

        debug!("Requesting {}...", &req);
        let client = reqwest::blocking::Client::new();
        let rsp = client.get(&req).header(USER_AGENT, PIN_UA).send()?;
        (rsp.status() == reqwest::StatusCode::OK)
            .as_option()
            .context(Http {
                ep: String::from(ep),
                status: rsp.status(),
            })?;
        let rsp = rsp.text()?;
        debug!("requesting {}...done: {}", req, rsp);

        let val = json::parse(&rsp)?;
        match val {
            json::JsonValue::Object(obj) => Ok(obj["result_code"].to_string()),
            _ => Err(Error::BadJsonType {
                item: val,
                back: Backtrace::generate(),
            }),
        }
    }
}
