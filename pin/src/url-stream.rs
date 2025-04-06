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

//! Produce a [`Stream`] of [`Url`]s.

use crate::pinboard;

use futures::future::{BoxFuture, FutureExt};
use pin_project::pin_project;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Deserializer;
use snafu::{prelude::*, Backtrace, IntoError};
use tokio::sync::Mutex; // Need to use this in order to hold a lock across wait-s
use tracing::{debug, error, trace, warn};

use std::{
    cmp::min,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("HTPP error {source}"))]
    Http {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Pinboard error {source}"))]
    Pinboard {
        source: pinboard::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Bad URL {source}"))]
    Url {
        source: url::ParseError,
        backtrace: Backtrace,
    },
}

type Result<T> = std::result::Result<T, Error>;

/// [`GreedyUrlStream`] is a state machine. [`Pending`] is a sum type representing the set of
/// states.
///
/// [`GreedyUrlStream`] accepts as input an iterator over items that can be either [`Url`]s or
/// [`Tag`]s. When it encounters a [`Tag`], it issues a call to the `/posts/all` endpoint,
/// scoped by tag, from which it produces more [`Url`]s. To implement this, [`GreedyUrlStream`]
/// moves through the following states.
///
/// In each case, we can't name the type that implements [`Future`], so we need a Trait object.
/// If I try to _require_ the Trait object to be Unpin, I get:
///
/// ```text
/// the trait `Unpin` is not implemented for `from_generator::GenFuture<[static
/// generator@src/lib.rs:664:89: 666:26]>`
/// ```
///
/// Future is not implemented for `Box<F: Future>`; it *is* for [`futures::BoxFuture`].
enum Pending {
    /// No outstanding tags; subsequent calls to [`poll_next`] will yield any previously
    /// "banked" [`Url`]s, until they are exhausted (at which point [`None`] will be returned).
    None,
    /// We've sent a `/post/all` request & are awaiting the response
    AwaitingResponse(BoxFuture<'static, pinboard::Result<reqwest::Response>>),
    /// We've received the response headers for our request for `/posts/all` and are awaiting
    /// the first body chunk.
    ProcessingResponseHeaders(
        (
            Arc<Mutex<reqwest::Response>>,
            BoxFuture<'static, reqwest::Result<Option<bytes::Bytes>>>,
        ),
    ),
    /// We've received the first chunk of the most recent response and are processing its
    /// successors.
    ProcessingResponseBody(
        (
            // The request whose body we're processing
            Arc<Mutex<reqwest::Response>>,
            // The Future resolving to the next chunk
            BoxFuture<'static, reqwest::Result<Option<bytes::Bytes>>>,
            // The parse buffer
            Vec<u8>,
            // Any bytes that need to be consumed from the parse buffer once it becomes large
            // enough (i.e. this value is greater than the size of the parse buffer ATM and we're
            // waiting for more bytes)
            usize,
        ),
    ),
}

/// Resposne type from Pinboard's `/posts/all` endpoint.
///
/// Example response:
///
/// ```json
/// {
///   "href": "https:\/\/www.sfchronicle.com\/bayarea\/article\/Napa-was-on-fire-A-winery-s-private-crew-was-16626998.php",
///   "description":"Napa was on fire. A winery's private crew was accused of wrongdoing. The case has exposed deep tensions in California",
///   "extended":"",
///   "meta":"7f1cc4538d3047b90452e5792ce650df",
///   "hash":"0af2a7ee48a8b92d8ca4bc4340739097",
///   "time":"2021-11-17T20:20:08Z",
///   "shared":"no",
///   "toread":"no",
///   "tags":"2020 cal-fire california ca-is-broken wildfire individuals-not-government"
/// }
/// ```
///
/// The only response attribute the implementation uses is `href`.
#[derive(Debug, Deserialize)]
struct Entry {
    href: String,
}

/// [`Stream`] implementation that takes as input a sequence of [`String`]s and produces a
/// seqeunce [`Url`]s for deletion.
///
/// Each [`String`] in the input sequence will first be interpreted as an [`Url`] and, if that is
/// succesful, the resulting [`Url`] will be yielded. If that fails, the input [`String`] will be
/// interpreted as a [`Tag`] or [`Tag`]s which will in turn be mapped to a sequence of [`Url`]s.
// LATER(sp1ff): If I remove this attribute, all hell breaks loose-- understand why.
#[pin_project]
pub struct GreedyUrlStream<I>
where
    I: Iterator<Item = String>,
{
    // TIL that reqwest::Client is easily clonable, so I made pinboard::Client that way too! No
    // lifetime!
    client: pinboard::Client,
    url_or_tags: I,
    /// [`Url`] instances that have been parsed already; each invocation of [`poll_next`] will
    /// produce members.
    banked_urls: VecDeque<Result<Url>>,
    /// [`url_or_tags`] `Item`s that can't be parsed as [`Url`]s are interpreted as [`Tag`]s
    /// which produce calls to `/posts/all` scoped by that [`Tag`]. As this instance moves
    /// through the phases of sending the request, receiving the response headers, and parsing
    /// the response body into [`Url`]s this member tracks our state.
    current_request: Pending,
}

impl<I> GreedyUrlStream<I>
where
    I: Iterator<Item = String>,
{
    /// Consume the iterator until we hit a [`Tag`] or [`Tag`]s, at which point we produce a
    /// request. Return a collection of the [`Url`]s we attempted to parse along with the
    /// appropriate value of [`Pending`].
    fn parse_urls_to_tag(
        client: &pinboard::Client,
        url_or_tags: &mut I,
    ) -> (VecDeque<Result<Url>>, Pending) {
        let mut banked_urls = VecDeque::new();
        let mut current_request = Pending::None;
        while let Some(item) = url_or_tags.next() {
            // I have a string... can I interpret it as an URL?
            match Url::parse(&item) {
                Ok(url) => banked_urls.push_back(Ok(url)),
                Err(_) => {
                    // Attempt to interpret `item` as one or more tags.
                    match item
                        .split("+")
                        .map(|text| pinboard::Tag::from_str(text))
                        .collect::<pinboard::Result<Vec<pinboard::Tag>>>()
                    {
                        Ok(tags) => {
                            let client_clone = client.clone();
                            current_request = Pending::AwaitingResponse(
                                async move { client_clone.all_posts(tags.iter().cloned()).await }
                                    .boxed(),
                            );
                            break;
                        }
                        Err(err) => banked_urls.push_back(Err(PinboardSnafu.into_error(err))),
                    }
                }
            }
        }
        (banked_urls, current_request)
    }

    /// Produce a [`GreedyUrlStream`] from a Pinboard [`Client`] and a sequence of
    /// [`String`]. Items will be interepreted as either [`Url`]s to be deleted, or [`Tag`]s
    /// whose associated posts will be deleted.
    pub fn new(client: pinboard::Client, mut url_or_tags: I) -> Result<GreedyUrlStream<I>> {
        let (banked_urls, current_request) =
            GreedyUrlStream::parse_urls_to_tag(&client, &mut url_or_tags);

        Ok(GreedyUrlStream {
            client: client,
            url_or_tags: url_or_tags,
            banked_urls: banked_urls,
            current_request: current_request,
        })
    }

    fn consume_more_urls_or_tags(&mut self) {
        let (banked_urls, current_request) =
            GreedyUrlStream::parse_urls_to_tag(&self.client, &mut self.url_or_tags);
        self.banked_urls.extend(banked_urls.into_iter());
        self.current_request = current_request;
    }
}

fn short_string(b: &[u8]) -> &str {
    std::str::from_utf8(&b[0..min(b.len(), 32)]).unwrap()
}

/// Take the current parse buffer, read as many [`Url`]s as possible out of it. Return the new parse
/// buffer, the results of parsing, and the number of bytes that should be skipped when the parse
/// buffer again becomes large enough (in general, this will be zero, but it could happen that the
/// current parse buffer _just_ contained an [`Entry`], and the suceeding ",\n" aren't available to
/// be skipped until the next chunk arrives).
// I need to reconsider how the parse buffer is carried around-- this implementation makes needless
// copies all over the place. I think it likely should be a bytes::MutBytes instance.
fn parse_urls_from_chunk(buf: &mut Vec<u8>) -> Result<(Vec<u8>, VecDeque<Url>, usize)> {
    trace!(
        "Starting to parse URLs: {}:{}...",
        buf.len(),
        short_string(&buf)
    );
    let mut urls = VecDeque::new();
    let mut bytes_to_consume = 0;
    loop {
        // Special case: if the request returned _zero_ posts, the response body will be "[]".
        // We've already popped the '[', so...
        if buf.len() == 1 && buf[0] == b']' {
            break;
        }
        let mut deser = Deserializer::from_slice(&buf).into_iter::<Entry>();
        // `deser.next()` returns an Option<Result<Entry, serde_json::Error>>.
        // So: first-off: did we parse anything:
        match deser.next() {
            None => {
                // We've exhausted the buffer; break out of the loop. We've consumed no bytes, so
                // leave the buffer where it is.
                break;
            }
            Some(result) => match result {
                Ok(entry) => {
                    let url = Url::parse(&entry.href).map_err(|err| UrlSnafu.into_error(err))?;
                    trace!("Parsed URL: {}", url.as_str());
                    urls.push_back(url);
                    let offset = deser.byte_offset();
                    drop(deser); // Let go of the immutable borrow of `&buf`, above.

                    // OK-- we've parsed an `Entry`, and we expect either ",\n" or "]" next. The
                    // thing is, we don't care: we want to just consume two more characters
                    // (i.e. assume ",\n") and if that's wrong, it'll be handled by the error case.

                    let mut split_at = offset + 2;
                    if offset == buf.len() {
                        // We "owe" two bytes
                        bytes_to_consume = 2;
                        split_at = offset;
                    } else if offset == buf.len() - 1 {
                        bytes_to_consume = 1;
                        split_at = offset + 1;
                    }
                    // Aaarrgghhhhh... makes a copy.
                    *buf = buf.split_off(split_at);
                }
                Err(err) => {
                    warn!("While deserializing URLs: {:#?}", err);
                    break;
                }
            },
        }
    }

    trace!("The buffer is now: {}:{}...", buf.len(), short_string(&buf));

    // One final, needless copy on the way out.
    Ok((buf.to_vec(), urls, bytes_to_consume))
}

fn poll_for_banked(banked_urls: &mut VecDeque<Result<Url>>) -> Poll<Option<Result<Url>>> {
    match banked_urls.pop_front() {
        Some(url) => Poll::Ready(Some(url)),
        None => Poll::Pending,
    }
}

fn handle_awaiting_response(res: pinboard::Result<reqwest::Response>) -> Result<Pending> {
    let rsp = res.map_err(|err| PinboardSnafu.into_error(err))?;
    let rsp = Arc::new(Mutex::new(rsp));
    let rsp_clone = rsp.clone();
    Ok(Pending::ProcessingResponseHeaders((
        rsp,
        async move { rsp_clone.lock().await.chunk().await }.boxed(),
    )))
}

fn handle_processing_response_headers(
    rsp: Arc<Mutex<reqwest::Response>>,
    mut chunk: bytes::Bytes,
) -> Result<(Pending, VecDeque<Url>)> {
    // We've got our first chunk! Consume the first '['
    // character & shift to `ProcessingResponseBody`. I suppose
    // we _could_ process this chunk here as well, but I'd
    // prefer to keep that logic in one place.
    let mut new_chunk: Vec<u8> = chunk.split_off(1).into_iter().collect();

    let (buf, urls, bytes_to_consume) = parse_urls_from_chunk(&mut new_chunk)?;

    let rsp_clone1 = rsp.clone();
    let rsp_clone2 = rsp.clone();
    Ok((
        Pending::ProcessingResponseBody((
            rsp_clone1,
            async move { rsp_clone2.lock().await.chunk().await }.boxed(),
            buf,
            bytes_to_consume,
        )),
        urls,
    ))
}

fn handle_processing_response_body(
    rsp: Arc<Mutex<reqwest::Response>>,
    bytes: bytes::Bytes,
    buf: &mut Vec<u8>,
    mut bytes_to_consume: usize,
) -> Result<(Pending, VecDeque<Url>)> {
    // serde-json works in terms of slices, so I don't see how to
    // avoid a copy. Maybe in the future I can build a thing that holds
    // a reference to the Vec & the Bytes and provides a Read implementation
    // over them.
    // `buf` is &Vec<u8>, `bytes` is Bytes
    buf.extend_from_slice(&bytes);
    let bytes_to_consume_this_time = min(bytes_to_consume, buf.len());
    if bytes_to_consume_this_time != 0 {
        *buf = buf.split_off(bytes_to_consume_this_time);
        bytes_to_consume -= bytes_to_consume_this_time;
    }

    let (buf, urls, bytes_to_consume_next_time) = parse_urls_from_chunk(buf)?;
    bytes_to_consume += bytes_to_consume_next_time;

    let rsp_clone1 = rsp.clone();
    let rsp_clone2 = rsp.clone();

    Ok((
        Pending::ProcessingResponseBody((
            rsp_clone1,
            async move { rsp_clone2.lock().await.chunk().await }.boxed(),
            buf,
            bytes_to_consume,
        )),
        urls,
    ))
}

impl<I> futures::stream::Stream for GreedyUrlStream<I>
where
    I: Iterator<Item = String>,
{
    type Item = Result<Url>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.current_request {
                Pending::None => {
                    return Poll::Ready(self.banked_urls.pop_front());
                }
                Pending::AwaitingResponse(box_fut) => {
                    // We are awaiting a response to our `/v1/posts` request.  `box_fut` is a:
                    //     &mut Pin<Box<dyn Future<Output=...> + 'static>>
                    // In order to call `poll()`, we need a Pin<P> where:
                    //   P: DerefMut
                    //   <P as Deref>::Target: Future
                    // I read this as "I need a Pin of a mutable reference to thing that
                    // implements Future", but that's not a Box! `Box<dyn Future>` only implements
                    // Future if the Trait object is Unpin (and ours does not).

                    // Deets at
                    // <https://stackoverflow.com/questions/60561573/how-can-one-await-a-result-of-a-boxed-future>

                    // This is non-lexical lifetimes coming into play. I have a mutable borrow
                    // of self (through the `current_request` member outstanding, and in order
                    // to `poll_for_banked()` below I need *another*. This should be illegal,
                    // but the borrowck can see that I'm not using the former borrow again
                    // before I return from this method, so it's cool. If I pass `&mut self`
                    // into a function the borrowck will complain. So I only factored-out the
                    // state-handling logic in the `Poll::Ready` branch.
                    match Pin::new(box_fut).poll(cx) {
                        Poll::Pending => {
                            // We're _still_ waiting, but if we have an Url "banked", we can at least
                            // return that.
                            return poll_for_banked(&mut self.banked_urls);
                        }
                        Poll::Ready(res) => {
                            // The future has resolved; we've got a Result<Response>
                            match handle_awaiting_response(res) {
                                Ok(curr_req) => {
                                    self.current_request = curr_req;
                                }
                                Err(err) => {
                                    return Poll::Ready(Some(Err(err)));
                                }
                            }
                        }
                    }
                }
                Pending::ProcessingResponseHeaders((rsp, box_fut)) => {
                    // We've got the response headers, we've requested the first body chunk, and
                    // we're waiting on its receipt.
                    debug!("ProcessingResponseHeaders");
                    match Pin::new(box_fut).poll(cx) {
                        Poll::Pending => {
                            // We're _still_ waiting, but if we have an Url "banked", we can at least
                            // return that.
                            return poll_for_banked(&mut self.banked_urls);
                        }
                        Poll::Ready(res) => {
                            // The future has resolved; we've got a Result<Option<Byte>> in `res`
                            let opt_chunk = match res {
                                Ok(opt_chunk) => opt_chunk,
                                Err(err) => {
                                    error!("While processing response headers: {:?}", err);
                                    self.consume_more_urls_or_tags();
                                    return Poll::Ready(Some(Err(HttpSnafu.into_error(err))));
                                }
                            };
                            // Now, it could be empty (if we asked for all posts by a tag that
                            // doesn't exist)
                            match opt_chunk {
                                None => {
                                    // No posts came back for this tag-- fine.
                                    warn!("No posts for this tag");
                                    self.consume_more_urls_or_tags();
                                }
                                Some(chunk) => {
                                    let (req, urls) = match handle_processing_response_headers(
                                        rsp.clone(),
                                        chunk,
                                    ) {
                                        Ok((req, urls)) => (req, urls),
                                        Err(err) => {
                                            error!("While parsing the response body: {:?}", err);
                                            self.consume_more_urls_or_tags();
                                            return Poll::Ready(Some(Err(err)));
                                        }
                                    };
                                    self.current_request = req;
                                    self.banked_urls.extend(urls.into_iter().map(|url| Ok(url)));
                                }
                            }
                        }
                    }
                }
                Pending::ProcessingResponseBody((rsp, box_fut, buf, bytes_to_consume)) => {
                    debug!("ProcessingResponseBody");
                    match Pin::new(box_fut).poll(cx) {
                        Poll::Pending => {
                            return poll_for_banked(&mut self.banked_urls);
                        }
                        Poll::Ready(res) => {
                            // The future has resolved; we have a Result<Option<Bytes>>
                            let res = match res {
                                Ok(res) => res,
                                Err(err) => {
                                    error!("While processing response body: {:?}", err);
                                    self.consume_more_urls_or_tags();
                                    return Poll::Ready(Some(Err(HttpSnafu.into_error(err))));
                                }
                            };
                            match res {
                                Some(bytes) => {
                                    debug!("Got a chunk of {} bytes.", bytes.len());
                                    let (req, urls) = match handle_processing_response_body(
                                        rsp.clone(),
                                        bytes,
                                        buf,
                                        *bytes_to_consume,
                                    ) {
                                        Ok((req, urls)) => (req, urls),
                                        Err(err) => {
                                            error!("While parsing the response body: {:?}", err);
                                            self.consume_more_urls_or_tags();
                                            return Poll::Ready(Some(Err(err)));
                                        }
                                    };
                                    self.current_request = req;
                                    self.banked_urls.extend(urls.into_iter().map(|url| Ok(url)));
                                }
                                None => {
                                    // We've processed the response entirely; IOW, we've processed the
                                    // current argument in `self.url_or_tags`-- grab some more.
                                    debug!("Finished parsing response body.");
                                    self.consume_more_urls_or_tags();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use itertools::intersperse;
    use test_log::test;
    use tracing::{error, info};

    use std::collections::HashMap;

    /// [Mockito]-like local HTTP server for testing [`GreedyUrlStream`].
    ///
    /// This struct will listen for HTTP requests on an arbitrary open port on `localhost`. It is
    /// capable of responding to two requests:
    ///
    /// 1. `GET /v1/posts/all` in which case it will respond with a list of Posts configured at
    /// construction time
    ///
    /// 2. `GET /v1/posts/delete` in which case it will note the URL that it was asked to delete
    ///
    /// The idea is that a unit test can whip-up a server instance with a pre-configured mapping of
    /// tags to URLs, instantiate a [`GreedyUrlStream`] on a client pointing to that instance and a
    /// sequence of tags & URLs, and ensure that the [`GreedyUrlStream`] implementation yields the
    /// correct sequence of URLs. Tests can also emit delete requests interleaved with the
    /// traversal, then check with the server instance to see that it got the correct sequence of
    /// delete requests.
    struct TestServer {
        addr: Url,
        tags: HashMap<String, Vec<String>>,
        deleted_urls: Vec<String>,
    }

    impl TestServer {
        pub async fn new<'a, T, U>(table: T) -> Arc<Mutex<TestServer>>
        where
            T: IntoIterator<Item = &'a (&'static str, U)>,
            // Kinda weird, but allows initialization from slices of &str
            U: IntoIterator<Item = &'a &'static str>,
            U: 'a + Copy,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let mut tags = HashMap::new();
            for (tag, urls) in table {
                tags.insert(
                    String::from(*tag),
                    urls.into_iter()
                        .map(|x: &&str| String::from(*x))
                        .collect::<Vec<String>>(),
                );
            }

            let base_url =
                Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
            let server = Arc::new(Mutex::new(TestServer {
                addr: base_url.clone(),
                tags: tags,
                deleted_urls: Vec::new(),
            }));

            let server_clone = server.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let inner_server = server_clone.clone();
                    let inner_url = base_url.clone();
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

                        let request = std::str::from_utf8(&incoming).expect("Non-UTF8 request");
                        debug!("TestServer got a request: {}", request);

                        if request.starts_with("GET /v1/posts/all") {
                            let idx = request.find("\r\n").unwrap();
                            let full_url = inner_url.join(&request[4..idx - 9]).unwrap();
                            let mut tag = None;
                            for pair in full_url.query_pairs() {
                                if pair.0 == "tag" {
                                    info!("listing all URLs with tag {}", pair.1);
                                    tag = Some(pair.1);
                                }
                            }
                            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n[").await.unwrap();
                            let tag = tag.unwrap().into_owned();
                            // This is kind of awful: it seems needlessly complex & makes copies all
                            // over the place.
                            let body = intersperse(inner_server.lock().await.tags.get(&tag).unwrap().iter()
                                .map(|url|
                                      format!("{{\"href\":\"{}\",\"description\":\"some description\",\"extended\":\"\",\"meta\":\"7f1cc4538d3047b90452e5792ce650df\",\"hash\":\"0af2a7ee48a8b92d8ca4bc4340739097\",\"time\":\"2021-11-17T20:20:08Z\",\"shared\":\"no\",\"toread\":\"no\",\"tags\":\"{} 2022\"}}", url, tag)
                                ), String::from(",\n"))
                                .fold(String::new(), |mut a, b| {
                                    a.push_str(&b);
                                    a
                                });
                            stream.write_all(body.as_bytes()).await.unwrap();
                            stream.write_all(b"]").await.unwrap();
                        } else if request.starts_with("GET /v1/posts/delete") {
                            let idx = request.find("\r\n").unwrap();
                            let full_url = inner_url.join(&request[4..idx - 9]).unwrap();
                            for pair in full_url.query_pairs() {
                                if pair.0 == "url" {
                                    info!("deleting Pinboard post {}", pair.1);
                                    inner_server.lock().await.deleted_urls.push(pair.1.into());
                                }
                            }
                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"result_code\":\"done\"}")
                                .await
                                .unwrap();
                        } else {
                            error!("TestServer 404!");
                            stream
                                .write_all(b"HTTP/1.1 404 Not Found\r\n")
                                .await
                                .unwrap();
                        }
                    });
                }
            });

            server
        }
        pub fn server_url(&self) -> Url {
            self.addr.clone()
        }
        pub fn deleted_urls(&self) -> Vec<String> {
            self.deleted_urls.clone()
        }
    }

    #[test(tokio::test)]
    async fn smoke() {
        let server = TestServer::new(&[
            ("foo", &["http://foo.com", "https://fooish.com"]),
            ("bar", &["http://bar.com", "https://barbinator.com"]),
        ])
        .await;

        let client;
        {
            let guard = server.lock().await;
            client =
                pinboard::Client::new(guard.server_url(), "sp1ff:FFFFFFFFFFFFFFFFFFFF").unwrap();
        }

        let mut my_stream = GreedyUrlStream::new(
            client.clone(),
            vec!["http://www.unwoundstack.com".to_string(), "foo".to_string()].into_iter(),
        )
        .unwrap();

        use futures::stream::StreamExt;
        while let Some(url) = my_stream.next().await {
            info!("My stream yielded {:?}", url);
            client.delete_post(url.unwrap()).await.unwrap();
        }

        assert_eq!(
            server.lock().await.deleted_urls(),
            vec![
                String::from("http://www.unwoundstack.com/"),
                String::from("http://foo.com/"),
                String::from("https://fooish.com/")
            ]
        );
    }
}

#[cfg(test)]
#[cfg(feature = "personal-link-tests")]
mod link_tests {

    use super::*;

    use tracing::{debug, error};

    use std::path::Path;

    /// [Mockito]-like local HTTP server for testing [`GreedyUrlStream`].
    ///
    /// This function will listen asynchronously for an HTTP request on an arbitrary open port on
    /// `localhost`. It expects a `GET /v1/posts/all` request to which it will respond with a body
    /// loaded from file.  This is behind a feature because I'm using actual response bodies that
    /// contain links of mine from [Pinboard.in] that I would prefer not to post to [Github].
    pub async fn test_server<P: AsRef<Path>>(pth: P, mut chunk_size: usize) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();

        let body = std::fs::read_to_string(pth).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut incoming = vec![];
            loop {
                let mut buf = vec![0u8; 1024];
                let read = stream.read(&mut buf).await.unwrap();
                incoming.extend_from_slice(&buf[..read]);
                if incoming.len() > 4 && &incoming[incoming.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }

            let request = std::str::from_utf8(&incoming).expect("Non-UTF8 request");
            debug!("TestServer got a request: {}", request);

            if request.starts_with("GET /v1/posts/all") {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/json; charset=utf8\r\n")
                    .await
                    .unwrap();
                // Now, write the body in chunks
                let nbytes = body.len();
                if nbytes < chunk_size {
                    stream
                        .write_all(format!("Content-Length: {}\r\n\r\n{}", nbytes, body).as_bytes())
                        .await
                        .unwrap();
                    debug!(
                        "Response body was less than chunk_size ({}); wrote in one shot & exiting.",
                        chunk_size
                    );
                } else {
                    stream
                        .write_all(b"Transfer-Encoding: chunked\r\n\r\n")
                        .await
                        .unwrap();
                    let mut nwritten = 0;
                    let mut bytes: &[u8] = body.as_bytes();
                    while nwritten < nbytes {
                        stream
                            .write_all(format!("{:X}\r\n", chunk_size).as_bytes())
                            .await
                            .unwrap();
                        stream.write_all(&bytes[0..chunk_size]).await.unwrap();
                        stream.write_all(b"\r\n").await.unwrap();
                        nwritten += chunk_size;
                        let (_, remaining) = bytes.split_at(chunk_size);
                        bytes = remaining;
                        if chunk_size > nbytes - nwritten {
                            chunk_size = nbytes - nwritten;
                        }
                    }
                    stream.write_all(b"0\r\n\r\n").await.unwrap();
                    debug!("All {} bytes written-- exiting.", nbytes);
                }
            } else {
                error!("TestServer 404!");
                stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\n")
                    .await
                    .unwrap();
            }
        });
        base_url
    }

    #[tokio::test]
    async fn linkedin_and_jira() {
        let url = test_server(&Path::new("linkedin-and-jira.json"), 4096).await;
        let client = pinboard::Client::new(url, "sp1ff:FFFFFFFFFFFFFFFFFFFF").unwrap();
        let stream =
            GreedyUrlStream::new(client, vec!["linkedin+jira".to_string()].into_iter()).unwrap();
        use futures::StreamExt;
        assert_eq!(stream.count().await, 4);
    }

    #[tokio::test]
    async fn linkedin() {
        let url = test_server(&Path::new("linkedin.json"), 4096).await;
        let client = pinboard::Client::new(url, "sp1ff:FFFFFFFFFFFFFFFFFFFF").unwrap();
        let mut stream =
            GreedyUrlStream::new(client, vec!["linkedin".to_string()].into_iter()).unwrap();
        use futures::StreamExt;
        // assert_eq!(stream.count().await, 330);
        let mut count = 0;
        while let Some(url) = stream.next().await {
            debug!("My stream yielded {:?}", url);
            count += 1;
        }
        assert_eq!(count, 331);
    }
}
