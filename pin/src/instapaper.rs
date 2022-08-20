// Copyright (C) 2020-2022 Michael Herstine <sp1ff@pobox.com>
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

//! Saving links to Instapaper.
//!
//! # Introduction
//!
//! This module provides a client for the [Simple Instapaper API]. The [Simple Instapaper API]
//! pretty much lets you add links to your [Instapaper] account & that's it:
//!
//! [Instapaper API]: https://www.instapaper.com/api/simple
//! [Instapaper]: https://www.instapaper.com
//!
//! ```
//! # tokio_test::block_on(async {
//! use pin::instapaper::{Client, Post};
//! let client = Client::new("https://www.instapaper.com", "jdoe", "c0fee").unwrap();
//! let post = Post::new("https://foo.com", Some("The frobinator"), Some("Some selection")).unwrap();
//! client.send_link(&post).await.expect_err("There is no jdoe with that password!");
//! # })
//! ```
//!
//! # Notes
//!
//! The Instapaper API advertises rate limits (although I haven't seen them enforced in the
//! wild). This client implementation only deals in individual requests; for retry & backoff logic,
//! see [`make_requests_with_backoff`].

use reqwest::{IntoUrl, StatusCode, Url};
use serde::Deserialize;
use snafu::{prelude::*, Backtrace};

use std::{collections::HashMap, fmt::Display};

type StdResult<T, E> = std::result::Result<T, E>;

/// Instapaper errors
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid URL for the Instapaper API: {source}"))]
    BadUrl {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("HTTP error: {source}"))]
    Http {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Instapaper API error {status}"))]
    Instapaper { status: reqwest::StatusCode },
    #[snafu(display("Instapaper JSON error: {source}"))]
    Json {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Rate limit exceeed/oo many requests"))]
    RateLimit,
}

type Result<T> = StdResult<T, Error>;

/// An Instapaper Simple API client
///
/// Construct [`Client`] instances with an API location & your username & password:
///
/// ```
/// use pin::instapaper::Client;
/// let client = Client::new("https://www.instapaper.com", "jdoe", "c0fee");
/// ```
///
/// The Instapaper API advertises rate limits (although I haven't seen them enforced in the
/// wild). This client implementation only deals in individual requests; for retry & backoff logic,
/// see [`make_requests_with_backoff`].
#[derive(Debug)]
pub struct Client {
    url: Url,
    client: reqwest::Client,
    username: String,
    password: String,
}

impl Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "Instapaper Client({}:{})", self.url, &self.username)
    }
}

#[derive(Debug)]
pub struct Post {
    url: Url,
    title: Option<String>,
    selection: Option<String>,
}

impl Display for Post {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "{{Instapaper Post: {}|{:#?}}}", self.url, self.title)
    }
}

impl Post {
    pub fn new<U: IntoUrl>(url: U, title: Option<&str>, selection: Option<&str>) -> Result<Post> {
        Ok(Post {
            url: url.into_url().context(BadUrlSnafu)?,
            title: title.and_then(|s| Some(s.into())),
            selection: selection.and_then(|s| Some(s.into())),
        })
    }
    pub fn url(&self) -> &Url {
        &self.url
    }
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().and_then(|s| Some(s.as_ref()))
    }
    pub fn selection(&self) -> Option<&str> {
        self.selection.as_ref().and_then(|s| Some(s.as_ref()))
    }
}

#[derive(Deserialize)]
struct Response {
    bookmark_id: usize,
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "{{Pinboard Response: {}}}", self.bookmark_id)
    }
}

impl Client {
    /// Construct a new [`Client`] instance.
    pub fn new<U: IntoUrl>(url: U, username: &str, password: &str) -> Result<Client> {
        use crate::vars::PIN_UA;
        Ok(Client {
            url: url.into_url().context(BadUrlSnafu {})?,
            client: reqwest::Client::builder()
                .user_agent(PIN_UA)
                .build()
                .context(HttpSnafu {})?,
            username: username.to_string(),
            password: password.to_string(),
        })
    }
    /// Send a new link to Instapaper, return the bookmark ID.
    #[tracing::instrument]
    pub async fn send_link(&self, post: &Post) -> Result<usize> {
        let mut params = HashMap::new();
        params.insert("url", post.url().as_str());
        if let Some(title) = post.title() {
            params.insert("title", title);
        }
        if let Some(selection) = post.selection() {
            params.insert("selection", selection);
        }
        let rsp = self
            .client
            .get(self.url.join("api/add").expect("Invalid URL in send_link"))
            .query(&params)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .context(HttpSnafu)?;
        // Grab the status code...
        let status = rsp.status();
        // before we consume the response.
        let rsp = rsp.json::<Response>().await.context(JsonSnafu)?;
        if status.is_success() {
            Ok(rsp.bookmark_id)
        } else if status == StatusCode::BAD_REQUEST {
            return Err(Error::RateLimit);
        } else {
            return InstapaperSnafu { status: status }.fail();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Matcher::UrlEncoded};
    use test_log::test;

    #[test(tokio::test)]
    async fn smoke() {
        // use RUST_LOG="trace,hyper::proto=off,hyper::client=off,mio::poll=off,want=off" cargo test
        let _mock = mockito::mock("GET", Matcher::Regex(r"/api/add.*$".to_string()))
            .match_query(mockito::Matcher::AllOf(vec![
                UrlEncoded(
                    "url".into(),
                    "https://unherd.com/thepost/liz-cheneys-neoconservatism-is-dead/".into(),
                ),
                UrlEncoded(
                    "title".into(),
                    "Liz Cheney's Neoconservativism is dead".into(),
                ),
                UrlEncoded("selection".into(), "Courtesy of pin 0.2!".into()),
            ]))
            .with_status(201)
            // there was also a date header: "date": "Thu, 18 Aug 2022 01:10:37 GMT",
            .with_header("content-type", "text/plain")
            .with_header("content-length", "42")
            .with_header("connection", "keep-alive")
            .with_header("server", "nginx/1.20.1")
            .with_header(
                "content-location",
                "https, //unherd.com/thepost/liz-cheneys-neoconservatism-is-dead/",
            )
            .with_header("x-powered-by", "AMT")
            .with_header("pragma", "no-cache")
            .with_header("cache-control", "no-cache")
            .with_header(
                "x-instapaper-title",
                "Liz Cheney's Neoconservativism is dead",
            )
            .with_body("{\"folders\": [], \"bookmark_id\": 1530380252}")
            .create();

        let client = Client::new(&mockito::server_url(), "sp1ff@pobox.com", "c0fee")
            .expect("Failed to build client");
        let post = Post::new(
            "https://unherd.com/thepost/liz-cheneys-neoconservatism-is-dead/",
            Some("Liz Cheney's Neoconservativism is dead"),
            Some("Courtesy of pin 0.2!"),
        )
        .unwrap();
        let id = client.send_link(&post).await.expect("Send-link failed");

        assert_eq!(id, 1530380252);
    }
}
