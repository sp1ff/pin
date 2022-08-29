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

//! Manage your Pinboard links
//!
//! You can produce documentation for this binary by saying `cargo doc --bin pin`. You may want to
//! specify a different `--target-dir` to avoid overwriting the library package's documentation. You
//! may want to add `--no-deps` to avoid (re)producing documentation for all the dependencies (which
//! would be produced for the library package, anyway). `make doc` will handle this all for you, if
//! you're working with the source distribution.

use pin::pinboard::Client;
use pin::{
    config::{Config, Target},
    get_tags,
    pinboard::{Tag, Title},
    url_stream::GreedyUrlStream,
    PinboardPost,
};
use reqwest::Url;

use clap::{App, Arg, ArgMatches};
use snafu::{Backtrace, IntoError, ResultExt, Snafu};
use tracing::{info, trace};

use std::path::{Path, PathBuf};
use std::str::FromStr;

type StdResult<T, E> = std::result::Result<T, E>;

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                         app error type                                         //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// `pin` errors
///
/// These will bubble up to the user (through `main`'s return value) so we do *not* derive the
/// [`Debug`] trait; instead we directly implement it so as to provide a nice, human-readable
/// message on `stderr`.
///
/// [`Debug`]: std::error::Error
#[derive(Snafu)]
enum Error {
    #[snafu(display("The link '{link}' could not be parsed as an URL: {source}"))]
    BadLink {
        link: String,
        source: url::ParseError,
        backtrace: Backtrace,
    },
    #[snafu(display(
        "While reading the configuration file {}, got {}.",
        cfg_file.to_string_lossy(),
        source
    ))]
    ConfigIo {
        cfg_file: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("No configuration file found at {}.", cfg_file.to_string_lossy()))]
    ConfigNotFound {
        cfg_file: PathBuf,
        backtrace: Backtrace,
    },
    #[snafu(display(
        "While reading the configuration file at {}, got {}.",
        cfg_file.to_string_lossy(),
        source
    ))]
    ConfigRead {
        cfg_file: PathBuf,
        source: toml::de::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Instapaper API error {source}"))]
    Instapaper { source: pin::instapaper::Error },
    #[snafu(display(
        "The link {link} contained no title, and you did not specify one with --title."
    ))]
    MissingTitle { link: String, backtrace: Backtrace },
    #[snafu(display("Unkown sub-command."))]
    NoSubCommand,
    #[snafu(display("You didn't specify a Pinboard API token on the command-line, the environment, or in your configuration file (if any). You can find your API key at https://pinboard.in/settings/password once you've signed-up & logged-in."))]
    NoToken,
    #[snafu(display("You asked `pin` to send a link to Instapaper, but you didn't specify your Instapaper username."))]
    NoUsername,
    #[snafu(display("You asked `pin` to send a link to Instapaper, but you didn't specify your Instapaper password."))]
    NoPassword,
    #[snafu(display("Application error: {source}"))]
    Pin {
        source: pin::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Pinboard API error {}", source))]
    Pinboard {
        source: pin::pinboard::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("While parsing the command arguments: {}", source))]
    UrlStream {
        source: pin::url_stream::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Target {name} is unknown."))]
    UnknownTarget { name: String, backtrace: Backtrace },
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n", self)?;
        if let Some(back) = snafu::ErrorCompat::backtrace(&self) {
            write!(f, "{}\n", back)?;
        }
        Ok(())
    }
}

type Result<T> = StdResult<T, Error>;

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                       utility functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Add the `get-tags` sub-command to the [`App`]
fn add_get_tags(app: App<'_>) -> App<'_> {
    app.subcommand(
    App::new("get-tags")
        .about("Retrieve all your Pinboard tags")
        .long_about(
            "Retrieve all your Pinboard tags along with their use counts & display them nicely.",
        )
        .arg(
            Arg::new("alphabetical")
                .short('a')
                .long("alphabetical")
                .help("Sort the tags lexicographically by tag name"),
        )
        .arg(
            Arg::new("csv")
                .short('c')
                .long("csv")
                .help("Produce output in CSV format"),
        )
        .arg(
            Arg::new("descending")
                .short('d')
                .long("descending")
                .help("Sort the output in descending order of use."),
        ))
}

/// Add the `send` sub-command to the [`App`]
fn add_send(app: App<'_>) -> App<'_> {
    app.subcommand(
        App::new("send")
            .about("Send an URL to Pinboard (and optionally to Instapaper)")
            .long_about("Send one or more URLs to Pinboard as well as, optionally, Intapaper.")
            .arg(
                Arg::new("target")
                    .short('r')
                    .long("target")
                    .help("pre-configured target for this link")
                    .long_help("Since one will likely re-use many of these options across invocations of this tool, it may be convenient to define them once in the configuration file & afterwards refer to that collection by name; we call such a pre-defined collection a \"target\". ")
                    .takes_value(true),
            )
            .arg(
                Arg::new("tag")
                    .short('t')
                    .long("tag")
                    .help("specify a tag to be applied-- may be given more than once")
                    .long_help("Tags may be up to 255 grapheme clusters in length and may not contain commas nor whitespace. Tags may be designated as private by beginning them with a '.'. More than one tag may be given by providing this option more than once (i.e. \"-t a -t b...\").")
                    .takes_value(true)
                    .multiple(true)
                    .number_of_values(1), // "-t a -t b...", not "-t a b..."
            )
            .arg(
                Arg::new("read-later")
                    .short('R')
                    .long("read-later")
                    .help("mark this pin as `read later'"),
            )
            .arg(
                Arg::new("title")
                    .short('T')
                    .long("title")
                    .help("link title")
                    .long_help("Titles may be given along with the links (in the form \"URL | TITLE\") or separately via this option. Note that if multiple URLS are given, this option's value will be applied to all arguments that don't specify a title.")
                    .takes_value(true),
            )
            .arg(
                Arg::new("url")
                    .index(1)
                    .help("URL to be sent to pinboard.in")
                    .long_help("You may specify one or more URLs to be sent to Pinboard. The argument may be given in one of two ways. The first is simply the URL, in which case the title will be taken from the -T option (which must be provided, in this case; it is illegal to send a link with no title). The other is to give an argument of the form \"URL | TITLE\" in which case the TITLE given in this argument will be preferred to the -T option.")
                    .multiple_values(true)
                    .required(true),
            )
            .arg(
                Arg::new("instapaper")
                    .long("with-instapaper")
                    .short('i')
                    .help("Send this link to Instapaper as well"),
            )
            .arg(
                Arg::new("username")
                    .long("username")
                    .short('u')
                    .help("Your Instapaper username")
                    .takes_value(true),
            )
            .arg(
                Arg::new("password")
                    .long("password")
                    .short('p')
                    .help("Your Instapaper password")
                    .takes_value(true),
            ),
    )
}

/// Add the `delete` sub-command to the [`App`]
fn add_delete(app: App<'_>) -> App<'_> {
    app.subcommand(
        App::new("delete")
            .about("Delete one or more URLs from Pinboard")
            .long_about("Delete one or more URLs from Pinboard (deletion from Instapaper is not available-- once you've posted to Instapaper, it's there forever).")
            .arg(Arg::new("dry-run")
                 .short('n')
                 .long("dry-run")
                 .help("Just print the URLs that would be deleted")
                 .long_help("Don't actually delete anything; just print the URLs that would be deleted"))
            .arg(
                Arg::new("url-or-tag")
                    .index(1)
                    .help("URL or tag to be deleted from Pinboard")
                    .long_help("The URLs to be deleted may be given in one of two ways; either as an explicit URL, or as a tag, in which case all URLs with that tag will be deleted")
                    .multiple_values(true)
                    .required(true),
            ),
    )
}

/// Add the `rename-tag` sub-command to the [`App`]
fn add_rename_tag(app: App<'_>) -> App<'_> {
    app.subcommand(
        App::new("rename-tag")
            .about("Rename a tag")
            .long_about("Rename a Pinboard tag as `rename-tag FROM TO`. Tags may be up to 255 grapheme clusters in length and may not contain commas nor whitespace. Tags may be designated as private by beginning them with a '.'")
            .arg(
                Arg::new("from")
                    .help("Source tag (i.e. the tag to be renamed)")
                    .index(1)
                    .requires("to")
                    .required(true),
            )
            .arg(
                Arg::new("to")
                    .help("Target tag name (i.e. the new name)")
                    .index(2)
                    .requires("from")
                    .required(true),
            ),
    )
}

/// Configure logging. This is still in-progress, but ATM the rules are:
///
/// 1. Configure defaults via command-line options:
///    - `-d` supercedes `-v`, which supercedes `-q`
///    - `-d` :=> sets the tracing level to DEBUG, `-v` to INFO, and `-q` to ERROR
/// 2. This can be overridden by the RUST_LOG environment variable
/// 3. If `-d` is given, use the HierarchicalLayer with a format that produces detailed,
/// syslog-style messages; otherwise just use a stock fmt Layer that produces human-friendly
/// output.
/// 4. If `-d` is given, add the ChromeLayer
fn configure_tracing(matches: &ArgMatches) {
    use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};
    use tracing_tree::HierarchicalLayer;

    let subscriber = Registry::default();

    let default_filter = if matches.is_present("debug") {
        "trace"
    } else if matches.is_present("verbose") {
        "debug"
    } else if matches.is_present("quiet") {
        "error"
    } else {
        "info"
    };

    let env_filter = EnvFilter::builder()
        .with_default_directive(default_filter.parse().unwrap())
        .from_env_lossy();

    let (mut simple_layer, mut hier_layer) = (None, None);
    if matches.is_present("debug") {
        hier_layer = Some(
            HierarchicalLayer::new(2)
                .with_targets(true)
                .with_bracketed_fields(true),
        );
    } else {
        simple_layer = Some(
            fmt::Layer::default()
                .pretty()
                .without_time()
                .with_level(false)
                .with_file(false)
                .with_line_number(false)
                .with_target(false),
        );
    }

    tracing::subscriber::set_global_default(
        subscriber
            .with(env_filter)
            .with(simple_layer)
            .with(hier_layer),
    )
    .expect("Failed to setup tracing");
}

fn make_app(dot_pin: Option<&mut PathBuf>) -> App<'_> {
    let mut cfg_arg = Arg::new("config")
        .short('c')
        .help("Specify a configuration file")
        .long_help("Certain global options as well as link targets (see `pin send --help`) can be specified in a configuration file for convenience.")
        .takes_value(true)
        .value_name("FILE");
    if let Some(pathb) = dot_pin {
        pathb.push(".pin");
        // This is lame; in addition to requiring that we can find a home directory for the current
        // user, we also require that the final path be UTF-8. This requirement is completely by
        // Clap's interface, which only allows a &str.
        if let Some(s) = pathb.to_str() {
            cfg_arg = cfg_arg.default_value(s);
        }
    }

    App::new("pin")
        .version(pin::vars::VERSION)
        .author(pin::vars::AUTHOR)
        .about("Manage your Pinboard links")
        .long_about("
`pin` is a small utility for managing your Pinboard links. It is by no means complete; it supports a few operations which the author has found useful. The complete list of sub-commands may be found below. Each sub-command takes the `--help` option for details on its usage. HTML documentation for the Rust crate may be found at https://docs.rs/pin/latest/pin/. User documentation may be found at https://www.unwoundstack.com/doc/pin/curr. If you installed `pin` from the source distribution, you can also say `info pin` to read the documentation in your Info viewer.
")
        .arg(
            Arg::new("token")
                .short('t')
                .long("token")
                .help("A pinboard.in API token for authentication purposes.")
                .long_help("Your pinboard.in API token for authentication purposes. You can find your API key at https://pinboard.in/settings/password once you've signed-up & logged-in.")
                .takes_value(true),
        )
        .arg(Arg::new("verbose").short('v').long("verbose").help("Enable more verbose output"))
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .help("Enable very verbose output")
                .long_help("Enable prolix output. This flag is intended for developer trouble-shooting.")
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .long("quiet")
                .help("Suppress all output other than errors"),
        )
        .arg(cfg_arg)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                          sub-commands                                          //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// `send` sub-command implementation
async fn send_tags(sub: &ArgMatches, cfg: Config, client: Client) -> Result<()> {
    // If they specified a target, and it doesn't exist, that's an error. If they just didn't
    // specify one, that's cool too.
    let target: Option<&Target> = match sub.get_one::<String>("target") {
        Some(tar_name) => Some(
            cfg.get_target(tar_name).ok_or(
                UnknownTargetSnafu {
                    name: (*tar_name).clone(),
                }
                .build(),
            )?,
        ),
        None => None,
    };

    let mut tags = match sub.get_many::<String>("tag") {
        Some(iter) => iter
            .cloned()
            .map(|s| -> Result<Tag> { Ok(Tag::try_from(s).context(PinboardSnafu)?) })
            .collect::<Result<Vec<Tag>>>()?,
        None => Vec::new(),
    };

    if let Some(target) = target {
        tags.extend(target.get_tags().cloned());
    }

    let read_later = if let Some(target) = target {
        target.read_later()
    } else {
        false
    };
    let read_later = read_later || sub.is_present("read-later");

    let insty = if sub.is_present("instapaper") {
        let env_username = std::env::var("INSTAPAPER_USERNAME");
        let username = sub
            .get_one::<String>("username")
            .or_else(|| match env_username.as_ref() {
                Ok(s) => Some(s),
                Err(_) => None,
            })
            .ok_or(Error::NoUsername)?;
        let env_password = std::env::var("INSTAPAPER_PASSWORD");
        let password = sub
            .get_one::<String>("password")
            .or_else(|| match env_password.as_ref() {
                Ok(s) => Some(s),
                Err(_) => None,
            })
            .ok_or(Error::NoPassword)?;
        Some(
            pin::instapaper::Client::new("https://www.instapaper.com", &username, &password)
                .context(InstapaperSnafu)?,
        )
    } else {
        None
    };

    let atom = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1000));

    // We build-up our collection of `Post`s before attempting to send; I chose to to this so
    // that any one argument that is invalid will be detected before we even start to send
    // requests. I suppose I could send all the legit links, and only fail when I discover a bad
    // one, but that sems inconvenient to the caller ("OK... I successfully posted *these*
    // links, then fix the bad one, then re-try everythign after...")
    let posts = sub
        .get_many::<String>("url")
        .unwrap() // This option is required
        .map(|arg| -> Result<PinboardPost> {
            // We need an iterator yielding Posts. Let's figure out the link & the title:
            let split: (&str, &str) = arg
                .find(" | ")
                .and_then(|idx| Some((&arg[0..idx], &arg[idx + 3..])))
                .or_else(|| {
                    sub.get_one::<String>("title")
                        .and_then(|title| Some((arg.as_ref(), title.as_ref())))
                })
                .ok_or(
                    MissingTitleSnafu {
                        link: (*arg).clone(),
                    }
                    .build(),
                )?;
            // `split.0` is a &str that should be an Url, and `split.1` is a &str that should be
            // a Title
            let pin_post = pin::pinboard::Post::new(
                Url::parse(split.0).context(BadLinkSnafu {
                    link: split.0.to_string(),
                })?,
                Title::from_str(split.1).context(PinboardSnafu {})?,
                tags.iter().cloned(),
                read_later,
            );

            let insty_post = match insty {
                Some(_) => Some(
                    pin::instapaper::Post::new(split.0, Some(split.1), Some(pin::vars::PIN_UA))
                        .context(InstapaperSnafu)?,
                ),
                None => None,
            };

            Ok(PinboardPost::new(
                &client,
                pin_post,
                insty
                    .as_ref()
                    .and_then(|client| Some((client, insty_post.unwrap(), atom.clone(), 1000, 5))),
            ))
        })
        .collect::<Result<Vec<PinboardPost>>>()?;

    pin::make_requests_with_backoff(posts.into_iter(), 3000, 10000, 5)
        .await
        .context(PinSnafu)
        .and_then(|_| Ok(()))
}

/// `delete` sub-command implementation
async fn delete_tags(sub: &ArgMatches, client: Client) -> Result<()> {
    let dry_run = sub.is_present("dry-run");
    let mut stream =
        GreedyUrlStream::new(client.clone(), sub.get_many("url-or-tag").unwrap().cloned()).unwrap();

    use futures::stream::StreamExt;
    let mut count = 0;
    while let Some(url) = stream.next().await {
        let url = url.context(UrlStreamSnafu)?;
        if dry_run {
            info!("Would delete {}", &url);
        } else {
            info!("Deleting {}", &url);
            client.delete_post(url).await.context(PinboardSnafu)?
        }
        count += 1;
    }

    if dry_run {
        info!("Would have deleted {} URLs.", count);
    } else {
        info!("Deleted {} URLs.", count);
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                          The Big Kahuna                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Specify a default value for `--config` IFF we can figure out the user's home directory.  It's
    // fine if we can't; but then we provide no default value for the option.
    let mut dot_pin = home::home_dir();

    // Build up the `App` object...
    let mut app = make_app(dot_pin.as_mut());
    app = add_get_tags(app);
    app = add_send(app);
    app = add_delete(app);
    app = add_rename_tag(app);

    // & parse the command line.
    let matches = app.get_matches(); // NB. --help & --version handled here (we won't return if
                                     // either was given)

    // Next-up: configure logging:
    configure_tracing(&matches);
    trace!("Logging is configured.");

    // Next-up-- configuration: one way or another, we're building ourselevs a `Config` instance. Do
    // we even have a `--config` option value? It will generally be defaulted, but won't be if we
    // couldn't figure out a home directory.
    let cfg: Config = match matches.get_one::<String>("config") {
        Some(cfg_path) => {
            // We do...  this could be an explicity value entered by the user, or it
            // could just be the default.
            match std::fs::read_to_string(Path::new(&cfg_path)) {
                // Either way, there's a file there-- attempt to interpret it.
                Ok(text) => toml::from_str(&text).context(ConfigReadSnafu {
                    cfg_file: PathBuf::from(cfg_path),
                })?,
                // Something went wrong. If we just got a default value, and the file's not there,
                // then just silently proceed to create a default `Config`. Otherwise, whether
                // there's a syntax error, or anything else, I figure the user probably wants to
                // know.
                Err(err) => match (err.kind(), matches.occurrences_of("config")) {
                    // They didn't specify a config file, and the default wasn't present. NBD, just
                    // create a default configuration.
                    (std::io::ErrorKind::NotFound, 0) => Config::default(),
                    // They _did_ specify a config file, and it wasn't found. Tell 'em:
                    (std::io::ErrorKind::NotFound, _) => {
                        return ConfigNotFoundSnafu {
                            cfg_file: PathBuf::from(cfg_path),
                        }
                        .fail();
                    }
                    // Urp?! Something else went wrong-- bail.
                    (_, _) => {
                        return Err(ConfigIoSnafu {
                            cfg_file: PathBuf::from(cfg_path),
                        }
                        .into_error(err));
                    }
                },
            }
        }
        None => Config::default(), // We have nada-- just whip-up a default instance.
    };

    let env_token = std::env::var("PINBOARD_API_TOKEN");
    let token = matches
        .get_one::<String>("token")
        .or_else(|| match env_token.as_ref() {
            Ok(s) => Some(s),
            Err(_) => None,
        })
        .ok_or(Error::NoToken)?;

    let client = Client::new("https://api.pinboard.in", token).context(PinboardSnafu)?;

    if let Some(sub) = matches.subcommand_matches("get-tags") {
        let alpha = sub.is_present("alphabetical");
        let desc = sub.is_present("descending");
        let csv = sub.is_present("csv");
        get_tags(&mut std::io::stdout(), &client, alpha, desc, csv)
            .await
            .context(PinSnafu)
    } else if let Some(sub) = matches.subcommand_matches("send") {
        send_tags(sub, cfg, client).await
    } else if let Some(sub) = matches.subcommand_matches("delete") {
        delete_tags(sub, client).await
    } else if let Some(sub) = matches.subcommand_matches("rename-tag") {
        let from = Tag::from_str(&sub.get_one::<String>("from").unwrap()).context(PinboardSnafu)?;
        let to = Tag::from_str(&sub.get_one::<String>("to").unwrap()).context(PinboardSnafu)?;
        client.rename_tag(&from, &to).await.context(PinboardSnafu)
    } else {
        Err(Error::NoSubCommand)
    }
}
