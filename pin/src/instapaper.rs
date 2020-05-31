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

//! instapaper -- Instapaper API client
//!
//! This module provides a rudimentary [Instapaper](https://www.instapaper.com)
//! [API](https://www.instapaper.com/api/simple) client.

use crate::error_from;
use crate::vars::PIN_UA;

use boolinator::Boolinator;
use json::JsonValue;
use log::debug;
use reqwest::header::USER_AGENT;
use serde_urlencoded::to_string as encode;
use snafu::{Backtrace, GenerateBacktrace, OptionExt, Snafu};

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
    #[snafu(display("While calling `{}' got {}", ep, status))]
    Http {
        ep: String,
        status: reqwest::StatusCode,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
    #[snafu(display(
        "Successfully added the URL to Instapaper, but the response contained no bookmark ID."
    ))]
    NoBookmarkId,
    #[snafu(display("Unexpected JSON response type {:#?}", item))]
    BadJsonResponseType {
        item: JsonValue,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
    #[snafu(display("Unexpected JSON response type {:#?}", item))]
    BadJsonValueType {
        item: JsonValue,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
}

error_from!(json::Error);
error_from!(reqwest::Error);
error_from!(serde_urlencoded::ser::Error);

pub type Result<T> = std::result::Result<T, Error>;

pub trait Instapaper {
    /// Send a single link to Instapaper
    fn send(&mut self, url: &str, title: Option<&str>) -> Result<String>;
}

pub struct Client {
    user: String,
    pass: String,
}

impl Client {
    pub fn new(username: &str, password: &str) -> Client {
        Client {
            user: username.to_string(),
            pass: password.to_string(),
        }
    }
}

impl Instapaper for Client {
    /// Send a single link to Instapaper
    fn send(&mut self, url: &str, title: Option<&str>) -> Result<String> {
        let ep = "/api/add";
        let mut args = vec![("url", url)];
        if let Some(title) = title {
            args.push(("title", title));
        }
        let req = format!("https://www.instapaper.com{}?{}", ep, encode(&args)?);

        let client = reqwest::blocking::Client::new();
        let rsp = client
            .get(&req)
            .header(USER_AGENT, PIN_UA)
            .basic_auth(&self.user, Some(&self.pass))
            .send()?;

        (rsp.status().is_success()).as_option().context(Http {
            ep: String::from(ep),
            status: rsp.status(),
        })?;

        let rsp = rsp.text()?;
        debug!("requesting {}...done: {}", req, rsp);

        let val = json::parse(&rsp)?;
        match val {
            JsonValue::Object(doc) => {
                let id = doc.get("bookmark_id").context(NoBookmarkId)?; // &JsonValue
                match id {
                    JsonValue::Short(n) => Ok(format!("new bookmark {}", n)),
                    _ => Err(Error::BadJsonValueType {
                        item: id.clone(),
                        back: Backtrace::generate(),
                    }),
                }
            }
            _ => Err(Error::BadJsonResponseType {
                item: val.clone(),
                back: Backtrace::generate(),
            }),
        }
    }
}
