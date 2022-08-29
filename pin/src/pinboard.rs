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

//! Managing Pinboard links
//!
//! # Introduction
//!
//! This module provides a client for [Pinboard]:
//!
//! [Pinboard]: https://pinboard.in
//!
//! ```
//! # tokio_test::block_on(async {
//! use pin::pinboard::{Client, Post, Tag, Title};
//! use reqwest::Url;
//! use std::str::FromStr;
//! let client = Client::new("https://api.pinboard.in", "jdoe:DECADE90C0DEDDABB1ED").unwrap();
//! let post = Post::new(Url::parse("http://foo.com").unwrap(),
//!                      Title::new("The Frobinator").unwrap(),
//!                      vec!["tag1", "tag2", "tag3"].iter().map(|s| Tag::from_str(s).unwrap()),
//!                      true);
//! client.send_post(&post).await.expect_err("Surely no one has that username & token?");
//! # })
//! ```
//!
//! # Notes
//! This implementation uses [version 1] of the Pinboard API.
//!
//! [version 1]: https://pinboard.in/api
//!
//! The Pinboard API advertises rate limits (although I haven't seen them enforced in the
//! wild). This client implementation only deals in individual requests; for retry & backoff logic,
//! see [`send_links_with_backoff`].

use reqwest::{IntoUrl, StatusCode, Url};
use serde::{Deserialize, Serialize};
use snafu::{prelude::*, Backtrace};
use unicode_segmentation::UnicodeSegmentation;

use std::collections::HashMap;
use std::fmt::{Debug, Display};

type StdResult<T, E> = std::result::Result<T, E>;

/// Pinboard-related errors
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid URL for the Pinboard API: {source}"))]
    BadUrl {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("HTTP error: {source}"))]
    Http {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("\"{text}\" is not a valid tag"))]
    InvalidTag { text: String, backtrace: Backtrace },
    #[snafu(display("\"{text}\" is not a valid title"))]
    InvalidTitle { text: String, backtrace: Backtrace },
    #[snafu(display("Pinboard API error: {status}"))]
    Pinboard {
        status: reqwest::StatusCode,
        backtrace: Backtrace,
    },
    #[snafu(display("Rate limit hit"))]
    RateLimit,
}

pub type Result<T> = StdResult<T, Error>;

struct Response(reqwest::Response);

impl std::convert::From<Response> for Result<()> {
    fn from(rsp: Response) -> Self {
        let status = rsp.0.status();
        if status.is_success() {
            return Ok(());
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(Error::RateLimit);
        } else {
            return PinboardSnafu { status: status }.fail();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                    Pinboard API data types                                     //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// An owned Pinboard-compliant tag.
///
/// Pinboard tags may be up to 255 ["logical characters"] in length and may not contain commas or
/// whitespace. By "logical character" I take the API docs to mean grapheme clusters, as all
/// entities are encoded as UTF-8. Furthermore, tags may be designated as ["private"] by starting
/// them with a ".".
///
/// ["logical characters"]: https://pinboard.in/api/#encoding
/// ["private"]: https://pinboard.in/tour/#privacy
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct Tag {
    // NB. We store the display form of the tag in `value`, so we need to maintain the internal
    // invariant that a private tag begins with a '.'
    value: String,
}

impl Tag {
    /// Create a new public [`Tag`]
    ///
    /// `text` may not begin with the '.' character, may not contain either the ',' character nor
    /// any whitespace, and must contain less than 256 grapheme clusters.
    pub fn new(text: &str) -> Result<Tag> {
        Tag::validate_text(text, 256)?;
        Ok(Tag { value: text.into() })
    }
    /// Create a new private Tag
    ///
    /// `text` may not begin with the '.' character, may not contain either the ',' character nor
    /// any whitespace, and must contain less than 255 grapheme clusters.
    pub fn private(text: &str) -> Result<Tag> {
        Tag::validate_text(text, 255)?;
        Ok(Tag {
            value: format!(".{}", text),
        })
    }
    /// Validate text as a Pinboard tag
    fn validate_text(text: &str, max_grapheme_clusters: usize) -> Result<()> {
        if text.contains(char::is_whitespace)
            || text.contains(',')
            || UnicodeSegmentation::graphemes(text, true).count() >= max_grapheme_clusters
        {
            return InvalidTagSnafu {
                text: text.to_string(),
            }
            .fail();
        }
        Ok(())
    }
}

impl std::convert::AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "{}", self.value)
    }
}

impl std::convert::TryFrom<String> for Tag {
    type Error = Error;
    fn try_from(s: String) -> StdResult<Self, Self::Error> {
        // Seems a bit too cute; couldn't wriggle-out of the clone() in the error case :(
        if '.' as u8
            == *s
                .as_bytes()
                .iter()
                .take(1)
                .next()
                .ok_or_else(|| InvalidTagSnafu { text: s.clone() }.build())?
        {
            Tag::validate_text(
                std::str::from_utf8(&s.as_bytes()[1..]).expect("Bad UTF-8"),
                254,
            )?;
            Ok(Tag { value: s })
        } else {
            Tag::validate_text(&s, 255)?;
            Ok(Tag { value: s })
        }
    }
}

impl std::convert::From<Tag> for String {
    fn from(t: Tag) -> Self {
        t.value
    }
}

impl std::str::FromStr for Tag {
    type Err = Error;
    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        Tag::try_from(s.to_string())
    }
}

/// An owned Pinboard-compliant title (or description)
///
/// Pinboard titles/descriptions may be up to 255 ["logical characters"] in length. By "logical
/// character" I take the API docs to mean grapheme clusters, as all entities are encoded as UTF-8.
///
/// ["logical characters"]: https://pinboard.in/api/#encoding
#[derive(Debug)]
pub struct Title {
    title: String,
}

impl Title {
    pub fn new(text: &str) -> Result<Title> {
        Title::validate_text(text)?;
        Ok(Title { title: text.into() })
    }
    /// Validate text as a Pinboard title
    fn validate_text(text: &str) -> Result<()> {
        if UnicodeSegmentation::graphemes(text, true).count() > 255 {
            return InvalidTitleSnafu {
                text: text.to_string(),
            }
            .fail();
        }
        Ok(())
    }
}

impl std::convert::AsRef<str> for Title {
    fn as_ref(&self) -> &str {
        &self.title
    }
}

impl Display for Title {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "{}", self.title)
    }
}

impl std::str::FromStr for Title {
    type Err = Error;
    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        Title::validate_text(s)?;
        Ok(Title { title: s.into() })
    }
}

#[cfg(test)]
mod entity_tests {
    use super::*;

    #[test]
    fn test_tag() {
        let x = Tag::new("foo");
        assert!(x.is_ok());
        let x = x.unwrap();
        assert_eq!(format!("{}", x), "foo");

        let x = Tag::private("bar");
        assert!(x.is_ok());
        let x = x.unwrap();
        assert_eq!(format!("{}", x), ".bar");

        // "好" is a single grapheme clsuter. That means I should be able to fit 255 of them
        // into a Tag, but not one more.
        let x = Tag::new(&"好".repeat(255));
        assert!(x.is_ok());
        let x = Tag::new(&"好".repeat(256));
        assert!(x.is_err());
        // and one fewer if it's private
        let x = Tag::private(&"好".repeat(254));
        assert!(x.is_ok());
        let x = Tag::private(&"好".repeat(255));
        assert!(x.is_err());

        // Finally, check the "comma & whitespace" condition
        let x = Tag::new("a,b");
        assert!(x.is_err());
        let x = Tag::new("a b");
        assert!(x.is_err());
    }
}

/// A Pinboard API client
///
/// Construct [`Client`] instances with the API location & your API token:
///
/// ```
/// use pin::pinboard::Client;
/// let client = Client::new("https://api.pinboard.in", "jdoe:DECADE90C0DEDDABB1ED");
/// ```
///
/// This implementation uses [version 1] of the Pinboard API.
///
/// [version 1]: https://pinboard.in/api
///
/// The Pinboard API advertises rate limits (although I haven't seen them enforced in the
/// wild). This client implementation only deals in individual requests; for retry & backoff logic,
/// see [`send_links_with_backoff`].
#[derive(Clone, Debug)]
pub struct Client {
    url: Url,
    client: reqwest::Client,
    token: String,
}

impl Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "Pinboard Client({}:{})", self.url, &self.token[0..8])
    }
}

/// A link and all of its associated metadata
#[derive(Debug)]
pub struct Post {
    /// The link itself
    link: Url,
    /// The link title
    title: Title,
    /// Tags associated with this link
    tags: Vec<Tag>,
    /// "Read later" bit
    read_later: bool,
}

impl Display for Post {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> StdResult<(), std::fmt::Error> {
        write!(f, "{{Pinboard Post: {}|{}}}", self.link, self.title)
    }
}

impl Post {
    pub fn new<I>(link: Url, title: Title, tags: I, read_later: bool) -> Post
    where
        I: Iterator<Item = Tag>,
    {
        Post {
            link: link,
            title: title,
            tags: tags.collect(),
            read_later: read_later,
        }
    }
}

impl Client {
    /// Construct a new [`Client`] instance.
    pub fn new<U: IntoUrl>(url: U, token: &str) -> Result<Client> {
        use crate::vars::PIN_UA;
        Ok(Client {
            url: url.into_url().context(BadUrlSnafu {})?,
            client: reqwest::Client::builder()
                .user_agent(PIN_UA)
                .build()
                .context(HttpSnafu {})?,
            token: token.to_string(),
        })
    }
    /// Retrieve all the account's tags together with their use count
    #[tracing::instrument]
    pub async fn get_all_tags(&self) -> Result<HashMap<String, usize>> {
        let rsp = self
            .client
            .get(
                self.url
                    .join("v1/tags/get")
                    .expect("Invalid URL in get_all_tags()"),
            )
            .query(&[("format", "json"), ("auth_token", &self.token)])
            .send()
            .await
            .context(HttpSnafu {})?;

        // At this point, I have the response status code & headers:
        if StatusCode::OK != rsp.status() {
            eprintln!("{:#?}", rsp);
            return PinboardSnafu {
                status: rsp.status(),
            }
            .fail();
        }

        Ok(rsp
            .json::<HashMap<String, usize>>()
            .await
            .context(HttpSnafu {})?)
    }
    /// Send a single post
    #[tracing::instrument]
    pub async fn send_post(&self, post: &Post) -> Result<()> {
        Response(
            self.client
                .get(
                    self.url
                        .join("v1/posts/add")
                        .expect("Invalid URL in send_posts()"),
                )
                .query(&[
                    ("url", post.link.as_ref()),
                    ("description", post.title.as_ref()),
                    (
                        "tags",
                        &post.tags.iter().fold(String::from(""), |mut acc, x| {
                            acc.push(' ');
                            acc.push_str(x.as_ref());
                            acc
                        }),
                    ),
                    (
                        "toread",
                        match post.read_later {
                            true => "yes",
                            false => "no",
                        },
                    ),
                    ("auth_token", &self.token),
                    ("format", "json"),
                ])
                .send()
                .await
                .context(HttpSnafu {})?,
        )
        .into()
    }
    /// Retrieve all posts; filter by zero or more tags. The docs say up to three tags are supported,
    /// but this implementation doesn't enforce that.
    #[tracing::instrument]
    pub async fn all_posts<T>(&self, mut tags: T) -> Result<reqwest::Response>
    where
        T: Iterator<Item = Tag> + Debug,
    {
        let mut query_params = vec![
            ("auth_token", self.token.clone()),
            ("format", "json".into()),
        ];
        while let Some(tag) = tags.next() {
            query_params.push(("tag", tag.into()));
        }
        Ok(self
            .client
            .get(
                self.url
                    .join("v1/posts/all")
                    .expect("Invalid URL in send_posts()"),
            )
            .query(&query_params)
            .send()
            .await
            .context(HttpSnafu)?)
    }
    #[tracing::instrument]
    pub async fn delete_post(&self, url: Url) -> Result<()> {
        Response(
            self.client
                .get(
                    self.url
                        .join("v1/posts/delete")
                        .expect("Invalid URL in delete_post()"),
                )
                .query(&[
                    ("url", url.as_ref()),
                    ("auth_token", &self.token),
                    ("format", "json"),
                ])
                .send()
                .await
                .context(HttpSnafu)?,
        )
        .into()
    }
    #[tracing::instrument]
    pub async fn rename_tag(&self, from: &Tag, to: &Tag) -> Result<()> {
        Response(
            self.client
                .get(
                    self.url
                        .join("/v1/tags/rename")
                        .expect("Invalid URL in rename_tag"),
                )
                .query(&[
                    ("old", from.as_ref()),
                    ("new", to.as_ref()),
                    ("format", "json"),
                ])
                .send()
                .await
                .context(HttpSnafu)?,
        )
        .into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mockito::Matcher;
    use test_log::test;

    #[test(tokio::test)]
    async fn test_get_all_tags() {
        // use RUST_LOG="mockito=debug" cargo test
        let _mock = mockito::mock("GET",
                                  Matcher::Regex(r"/v1/tags/get.*$".to_string()))
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("format".into(), "json".into()),
                mockito::Matcher::UrlEncoded(
                    "auth_token".into(),
                    "sp1ff:FFFFFFFFFFFFFFFFFFFF".into(),
                ),
            ]))
            .with_status(200)
            // // N.B. The real response also includes a date header, like "Sun, 07 Aug 2022 14:33:31 GMT"
            .with_header("content-type", "text/json; charset=utf-8")
            .with_header("server", "Apache/2.4.18 (Ubuntu)")
            .with_body("{\"1997\":1,\"2012\":1,\"2017\":1,\"2018\":3,\"2019\":6,\"2020\":51,\"2020-08-24\":1,\"2021\":103,\"2021-recall\":1}\t")
            .create();

        let client = Client::new(&mockito::server_url(), "sp1ff:FFFFFFFFFFFFFFFFFFFF").unwrap();
        let rsp = client.get_all_tags().await;
        assert!(rsp.is_ok());
        let rsp = rsp.unwrap();
        assert_eq!(rsp.get("2020"), Some(&51));
    }
}
