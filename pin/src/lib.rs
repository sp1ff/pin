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

//! pin -- a crate for managing your Pinboard links
//!
//! # Introduction
//!
//! [`pin`] is a crate for working with [Pinboard] and, optionally, [Instapaper]. For instance,
//! to send a link to Pinboard:
//!
//! [Pinboard]: https://pinboard.in
//! [Instapaper]: https://www.instapaper.com
//!
//! ``` ignore
//! use pin::pinboard::{Client, Post, Tag, Title};
//! use reqwest::Url;
//! use std::str::FromStr;
//! let client = Client::new("https://api.pinboard.in", "jdoe:DECADE90C0DEDDABB1ED").unwrap();
//! let post = Post::new(Url::parse("http://foo.com").unwrap(),
//!                      Title::new("The Frobinator").unwrap(),
//!                      vec!["tag1", "tag2", "tag3"].iter().map(|s| Tag::from_str(s).unwrap()),
//!                      true);
//! client.send_post(&post).await.expect_err("Surely no one has that username & token?");
//! ```
//!
//! It is a small crate I wrote primarily to support my own workflow, and currently is used in the
//! implementation of the [`pin`] CLI tool.
//!
//! [`pin`]: https://www.unwoundstack.com/doc/pin/curr
//!
//! # Retries & Backoff
//!
//! Both the [Pinboard] & [Instapaper] APIs reserve the right to rate-limit callers. In the case of
//! Pinboard, the advertised acceptable rate for most endpoints is one request every three seconds
//! (much worse for a few selected endpoints), but I've seen far better than that in the wild. The
//! [docs] suggest: "Make sure your API clients check for 429 Too Many Requests server errors and
//! back off appropriately. If possible, keep doubling the interval between requests until you stop
//! receiving errors."
//!
//! [docs]: https://pinboard.in/api/
//!
//! Instapaper is a bit more coy, only [alluding] to rate-limiting in their documentation for a 400
//! response code as being returned for "a bad request or exceeded the rate limit". The rate limit
//! is never defined, and I have never encountered it in the wild.
//!
//! [alluding]: https://www.instapaper.com/api/simple
//!
//! Regardless, you can use [`make_requests_with_backoff`] to make one or more requests with retries
//! and (linear) backoff.

pub mod config;
pub mod instapaper;
pub mod pinboard;
pub mod vars;

use async_trait::async_trait;
use snafu::{IntoError, ResultExt, Snafu};
use strfmt::strfmt;
use tracing::{debug, trace};

use std::{cmp::max, collections::HashMap, fmt::Debug, sync::atomic::Ordering};

type StdResult<T, E> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{}", source))]
    Io { source: std::io::Error },
    #[snafu(display("The maximum number of retries was exceeded"))]
    MaxRetriesExceeded,
    #[snafu(display("Pinboard API error {}", source))]
    Pinboard { source: pinboard::Error },
    #[snafu(display("While sending, got {}", source))]
    Send { source: SendError },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Get all Pinboard.in tags & pretty-print 'em
#[tracing::instrument]
pub async fn get_tags<W: std::io::Write + std::fmt::Debug>(
    out: &mut W,
    client: &pinboard::Client,
    alpha: bool,
    desc: bool,
    csv: bool,
) -> Result<()> {
    let mut tags = client
        .get_all_tags()
        .await
        .context(PinboardSnafu)?
        .drain()
        .map(|(k, v)| (k, v))
        .collect::<Vec<(String, usize)>>();
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
            writeln!(out, "{}", strfmt(&fmt, &hdrvars).unwrap()).context(IoSnafu)?;

            writeln!(out, "{}", rule).context(IoSnafu)?;

            for tag in &tags {
                let s = format!("{}", tag.1);
                let mut vars: HashMap<String, &str> = HashMap::new();
                vars.insert(String::from("tag"), &tag.0);
                vars.insert(String::from("uc"), &s);
                writeln!(out, "{}", strfmt(&fmt, &vars).unwrap()).context(IoSnafu)?;
            }

            writeln!(out, "{}", rule).context(IoSnafu)?;
        }
        None => {
            // We're printing in CSV
            for tag in &tags {
                writeln!(out, "{},{}", tag.0, tag.1).context(IoSnafu)?;
            }
        }
    }

    Ok(())
}

/// Make a series of requests to an API, with retries & linear backoff.
///
/// Both the [Pinboard] & [Instapaper] APIs reserve the right to rate-limit callers. In the case of
/// Pinboard, the advertised acceptable rate for most endpoints is one request every three seconds
/// (much worse for a few selected endpoints), but I've seen far better than that in the wild. The
/// [docs] suggest: "Make sure your API clients check for 429 Too Many Requests server errors and
/// back off appropriately. If possible, keep doubling the interval between requests until you stop
/// receiving errors."
///
/// [docs]: https://pinboard.in/api/
///
/// Instapaper is a bit more coy, only [alluding] to rate-limiting in their documentation for a 400
/// response code as being returned for "a bad request or exceeded the rate limit". The rate limit
/// is never defined, and I have never encountered it in the wild.
///
/// [alluding]: https://www.instapaper.com/api/simple
///
/// Regardless, this implementation will take into account the possibility of rate-limiting by
/// retrying on certain status codes, halving the request rate each time. At the same time it tires
/// to take advantage of the fact that they don't seem widely enforced by increasing the request
/// rate on success. Expressed in pseudo-code:
///
/// ```text
/// LET BETA := the wait time between API requests (say, 3 sec)
/// LET REQS := an Iterator over >=0 requests
/// WHILE REQS
///   let LAST_SENT := NOW()
///   send REQS.curr()
///   match response
///     success :=> {
///       BETA := BETA / 2;
///       REQS = REQS.next()
///     }
///     429 Too Many Requests :=> BETA *= 2;
///     else :=> fail
///   end
///   if REQS {
///     wait BETA_PIN - (NOW() - LAST_SENT_PIN)
///   }
/// return BETA
/// ```
///
/// In order to abstract over the particular request being made (and even API being hit), this
/// implementation works in tems of the [`Sender`] trait.
#[tracing::instrument]
pub async fn make_requests_with_backoff<I, T>(
    mut reqs: I,
    mut beta_ms: u64,
    max_beta_ms: u64,
    max_retries: usize,
) -> Result<u64>
where
    I: Iterator<Item = T> + Debug,
    T: Sender + Debug,
{
    use std::time::SystemTime;

    let mut retries = 0;
    let mut req = reqs.next();
    while let Some(post) = &req {
        let last_sent = SystemTime::now();
        match post.send().await {
            Ok(_) => {
                beta_ms = beta_ms / 2;
                trace!("beta :=> {}", beta_ms);
                req = reqs.next();
            }
            Err(SendError::TooManyRequests) => {
                beta_ms = beta_ms.checked_mul(2).unwrap_or(max_beta_ms);
                trace!("beta :=> {}", beta_ms);
                retries = retries + 1;
                if retries > max_retries {
                    return Err(Error::MaxRetriesExceeded);
                }
            }
            Err(err) => {
                return Err(SendSnafu.into_error(err));
            }
        }
        if req.is_some() {
            let elapsed: u128 = SystemTime::now()
                .duration_since(last_sent)
                .unwrap()
                .as_millis();
            let elapsed: u64 = u64::try_from(elapsed).unwrap();
            trace!("elapsed is {}", elapsed);
            let backoff = beta_ms.checked_sub(elapsed).unwrap();
            debug!("Sleeping for {}ms...", backoff);
            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            debug!("Sleeping for {}ms...done.", backoff);
        }
    }

    Ok(beta_ms)
}

/// [`Sender`] implementations can fail in one of two ways: we were rate-limited or "something else
/// went wrong"
#[derive(Debug, Snafu)]
pub enum SendError {
    #[snafu(display("Rate-limited"))]
    TooManyRequests,
    #[snafu(display("Request failure: {source}"))]
    Failure { source: Box<dyn std::error::Error> },
}

/// An entity that can send a single request with two failure modes: rate-limited, and everything
/// else
#[async_trait]
pub trait Sender {
    async fn send(&self) -> StdResult<(), SendError>;
}

/// Post a link to the [Instapaper] API
///
/// [Instapaper]: https://www.instapaper.com
#[derive(Debug)]
pub struct InstapaperPost<'a> {
    client: &'a instapaper::Client,
    post: instapaper::Post,
}

#[async_trait]
impl<'a> Sender for &InstapaperPost<'a> {
    async fn send(&self) -> StdResult<(), SendError> {
        match self.client.send_link(&self.post).await {
            Ok(_) => Ok(()),
            Err(instapaper::Error::RateLimit) => Err(SendError::TooManyRequests),
            Err(err) => Err(FailureSnafu.into_error(Box::new(err))),
        }
    }
}

impl<'a> InstapaperPost<'a> {
    pub fn new(client: &'a instapaper::Client, post: instapaper::Post) -> InstapaperPost<'a> {
        InstapaperPost {
            client: client,
            post: post,
        }
    }
}

/// Post to the [Pinboard] API, and optionally the [Instapaper] API
///
/// [Pinboard]: https://pinboard.in
/// [Instapaper]: https://www.instapaper.com
#[derive(Debug)]
pub struct PinboardPost<'a, 'b> {
    client: &'a pinboard::Client,
    post: pinboard::Post,
    insty: Option<(
        InstapaperPost<'b>,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
        u64,
        usize,
    )>,
}

#[async_trait]
impl<'a, 'b> Sender for PinboardPost<'a, 'b> {
    /// Send a link to [Pinboard]. If so configured, call [`make_requests_with_backoff`] with the
    /// optional [Instapaper] link.
    ///
    /// [Pinboard]: https://pinboard.in
    /// [Instapaper]: https://www.instapaper.com
    async fn send(&self) -> StdResult<(), SendError> {
        match self.client.send_post(&self.post).await {
            Ok(_) => {
                if let Some((insty_post, beta, max_beta, max_retries)) = &self.insty {
                    let new_beta = make_requests_with_backoff(
                        std::iter::once(insty_post),
                        beta.load(Ordering::Relaxed),
                        *max_beta,
                        *max_retries,
                    )
                    .await
                    .map_err(|err| FailureSnafu.into_error(Box::new(err)))?;
                    beta.store(new_beta, Ordering::Relaxed);
                }
                Ok(())
            }
            Err(pinboard::Error::RateLimit) => Err(SendError::TooManyRequests),
            Err(err) => Err(FailureSnafu.into_error(Box::new(err))),
        }
    }
}

impl<'a, 'b> PinboardPost<'a, 'b> {
    pub fn new(
        pin_client: &'a pinboard::Client,
        pin_post: pinboard::Post,
        instapaper: Option<(
            &'b instapaper::Client,
            instapaper::Post,
            std::sync::Arc<std::sync::atomic::AtomicU64>,
            u64,
            usize,
        )>,
    ) -> PinboardPost<'a, 'b> {
        PinboardPost {
            client: pin_client,
            post: pin_post,
            insty: instapaper.and_then(|(client, post, atom, max_beta, max_retries)| {
                Some((
                    InstapaperPost::new(client, post),
                    atom,
                    max_beta,
                    max_retries,
                ))
            }),
        }
    }
}
#[cfg(test)]
mod test {

    use super::*;

    use reqwest::{StatusCode, Url};
    use test_log::test;
    use tracing::error;

    use std::{
        collections::VecDeque,
        str::FromStr,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    /// A Mockito-style server that mocks the Pinboard & Instapaper APIs
    ///
    /// Mockito's pretty cool for mocking an individual request/response pair, but provides no
    /// support for multi-request conversations. I cooked this up to test my backoff & retry logic.
    struct MockTestServer {
        addr: Url,
        expected: VecDeque<(String, StatusCode)>,
        deltas: Vec<Duration>,
        last_received: Option<SystemTime>,
    }

    impl MockTestServer {
        /// Start an async server that expects a certain sequence of requests & will respond with
        /// pre-loaded responses so long as it continues to receive expected input.
        pub async fn new<'a, I>(iter: I) -> Arc<Mutex<MockTestServer>>
        where
            I: IntoIterator<Item = &'a (&'static str, StatusCode)>,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let mock = Arc::new(Mutex::new(MockTestServer {
                addr: Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
                expected: iter
                    .into_iter()
                    .map(|pair| (pair.0.into(), pair.1))
                    .collect::<VecDeque<(String, StatusCode)>>(),
                deltas: Vec::new(),
                last_received: None,
            }));

            let server_mock = mock.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let inner_mock = server_mock.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut incoming = vec![];
                        loop {
                            let mut buf = vec![0u8; 1024];
                            let read = stream.read(&mut buf).await.unwrap();
                            incoming.extend_from_slice(&buf[..read]);
                            if incoming.len() > 4 && &incoming[incoming.len() - 4..] == b"\r\n\r\n"
                            {
                                break;
                            }
                        }

                        let now = SystemTime::now();
                        let incoming = std::str::from_utf8(&incoming).unwrap();

                        // Pop the next expected request off the inner_mock:
                        let expected;
                        {
                            let inner_mock = inner_mock.lock();
                            expected = inner_mock.unwrap().pop_front();
                        }

                        if incoming.starts_with(&expected.0) {
                            stream
                                .write_all(
                                    format!(
                                        "HTTP/1.1 {}\r\n\r\n{}\r\n",
                                        expected.1,
                                        if expected.0 == "/v1/posts/add" {
                                            "{\"result_code\":\"done\"}"
                                        } else {
                                            "{\"bookmark_id\": 1530898236}"
                                        }
                                    )
                                    .as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else {
                            stream
                                .write_all(b"HTTP/1.1 428 Precondition Required\r\n")
                                .await
                                .unwrap();
                        }

                        {
                            let mut inner_mock = inner_mock.lock().unwrap();
                            inner_mock.note_receipt_of_request(now);
                        }
                    });
                }
            });
            mock
        }
        pub fn deltas(&self) -> Vec<Duration> {
            self.deltas.clone()
        }
        pub fn note_receipt_of_request(&mut self, recvd: SystemTime) {
            if let Some(last_received) = self.last_received {
                self.deltas
                    .push(recvd.duration_since(last_received).unwrap())
            }
            self.last_received = Some(recvd);
        }
        pub fn pop_front(&mut self) -> (String, StatusCode) {
            self.expected.pop_front().unwrap()
        }
        pub fn server_url(&self) -> Url {
            self.addr.clone()
        }
    }

    #[test(tokio::test)]
    async fn backoff_test() {
        let mock = MockTestServer::new(&[
            ("GET /v1/posts/add", StatusCode::TOO_MANY_REQUESTS), // N/A
            ("GET /v1/posts/add", StatusCode::OK),                // 6000
            ("GET /api/add", StatusCode::OK),                     // 0
            ("GET /v1/posts/add", StatusCode::OK),                // 3000
            ("GET /api/add", StatusCode::BAD_REQUEST),            // 0
            ("GET /api/add", StatusCode::BAD_REQUEST),            // 1000
            ("GET /api/add", StatusCode::OK),                     // 2000
        ])
        .await;

        let insty_client;
        let pin_client;

        {
            let guard = mock.lock().unwrap();
            pin_client =
                pinboard::Client::new(guard.server_url(), "sp1ff:FFFFFFFFFFFFFFFFFFFF").unwrap();
            insty_client = instapaper::Client::new(guard.server_url(), "sp1ff@pobox.com", "c0fee")
                .expect("Failed to build client");
        }

        let atom = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1000));

        make_requests_with_backoff(
            vec![
                PinboardPost::new(
                    &pin_client,
                    pinboard::Post::new(
                        Url::parse("https://foo.com").unwrap(),
                        pinboard::Title::from_str("Frobinator").unwrap(),
                        vec![].into_iter(),
                        true,
                    ),
                    Some((
                        &insty_client,
                        instapaper::Post::new("https://foo.com", Some("Frobinator"), None).unwrap(),
                        atom.clone(),
                        10000,
                        5,
                    )),
                ),
                PinboardPost::new(
                    &pin_client,
                    pinboard::Post::new(
                        Url::parse("https://bar.com").unwrap(),
                        pinboard::Title::from_str("Bar none!").unwrap(),
                        vec![].into_iter(),
                        true,
                    ),
                    Some((
                        &insty_client,
                        instapaper::Post::new("https://bar.com", Some("Bar none!"), None).unwrap(),
                        atom.clone(),
                        10000,
                        5,
                    )),
                ),
            ]
            .into_iter(),
            3000,
            10000,
            5,
        )
        .await
        .unwrap_or_else(|err| {
            error!("{}", err);
            panic!();
        });

        let deltas;
        {
            deltas = mock.lock().unwrap().deltas();
        }

        assert_eq!(6, deltas.len());
        assert!(deltas[0].as_millis().checked_sub(6000).unwrap() <= 10);
        assert!(deltas[1].as_millis() <= 10);
        assert!(deltas[2].as_millis().checked_sub(3000).unwrap() <= 10);
        assert!(deltas[3].as_millis() <= 10);
        assert!(deltas[4].as_millis().checked_sub(1000).unwrap() <= 10);
        assert!(deltas[5].as_millis().checked_sub(2000).unwrap() <= 10);
    }
}
