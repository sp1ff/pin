// Copyright (C) 2020-2021 Michael Herstine <sp1ff@pobox.com>
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

// It seems I can't document main.rs without conflicting with lib.rs? Oh, well: the tool should
// be self-documenting, anyway.

use pin::error_from;
use pin::Config;
use pin::{get_tags, rename_tag, send_link};

use clap::{App, Arg};
use log::{trace, LevelFilter};
use log4rs::{
    append::console::{ConsoleAppender, Target},
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
};
use snafu::{Backtrace, GenerateBacktrace, OptionExt, ResultExt, Snafu};

use std::path::Path;

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                         app error type                                         //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Application errors; these will bubble up to the user, so we do *not* derive the Debug trait;
/// instead we directly implement it on this type to provide nice, human-readable messages on
/// stderr.
#[derive(Snafu)]
enum Error {
    #[snafu(display("{}", cause))]
    Other {
        #[snafu(source(true))]
        cause: Box<dyn std::error::Error>,
        #[snafu(backtrace(true))]
        back: Backtrace,
    },
    /// Conflicting verbosity options
    #[snafu(display("Only one of -v, -d & -q may be given"))]
    BadVerbosity,
    /// The given configuration file wasn't found
    #[snafu(display("The given configuration file `{}' wasn't found.", cfg_file))]
    ConfigNotFound { cfg_file: String },
    /// Error reading configuration file
    #[snafu(display("While reading {}, got {}", cfg_file, cause))]
    ConfigRead {
        cfg_file: String,
        #[snafu(source(true))]
        cause: toml::de::Error,
    },
    #[snafu(display("Couldn't extract the config argument."))]
    NoConfig,
    /// Couldn't figure out the user's home directory
    #[snafu(display("Have you set $HOME ({})?", cause))]
    NoHome {
        #[snafu(source(true))]
        cause: std::env::VarError,
    },
    /// No sub-command specified
    #[snafu(display("No sub-command given; try `pin --help'."))]
    NoSubCommand,
    /// No token for the Pinboard API found
    #[snafu(display(
        "No token for the Pinboard API was found on the command-line, environment, \
or in configuration."
    ))]
    NoToken,
    #[snafu(display(
        "No Instapaper password was found on the command-line, \
                     environment, or configuration."
    ))]
    NoPassword,
    #[snafu(display(
        "No Instapaper username was found on the command-line, \
                     environment, or configuration."
    ))]
    NoUsername,
    #[snafu(display("No target named `{}'.", target))]
    UnknownTarget { target: String },
    #[snafu(display("You didn't specify a title."))]
    NoTitle,
}

error_from!(log::SetLoggerError);
error_from!(pin::Error);
error_from!(std::env::VarError);
error_from!(std::io::Error);

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n", self)?;
        if let Some(back) = snafu::ErrorCompat::backtrace(&self) {
            write!(f, "{}\n", back)?;
        }
        Ok(())
    }
}

fn add_subcommands(app: clap::App) -> clap::App {
    app.subcommand(
        App::new("get-tags")
            .about("Retrieve all your Pinboard tags along with their use counts")
            .arg(
                Arg::new("alphabetical")
                    .short('a')
                    .about("Sort the output lexicographically"),
            )
            .arg(
                Arg::new("csv")
                    .short('c')
                    .about("Produce output in CSV format"),
            )
            .arg(
                Arg::new("descending")
                    .short('d')
                    .about("Sort the output in descending order of use"),
            ),
    )
    .subcommand(
        App::new("rename-tag")
            .arg(
                Arg::new("from")
                    .about("Source tag (i.e. the tag to be renamed)")
                    .index(1)
                    .requires("to")
                    .required(true),
            )
            .arg(
                Arg::new("to")
                    .about("Target tag name (i.e. the new name)")
                    .index(2)
                    .requires("from")
                    .required(true),
            ),
    )
    .subcommand(
        App::new("send")
            .about("Send an URL to pinboard (and optionally Instapaper)")
            .arg(
                Arg::new("target")
                    .short('r')
                    .long("target")
                    .about("pre-configured target for this link")
                    .takes_value(true),
            )
            .arg(
                Arg::new("tag")
                    .short('t')
                    .long("tag")
                    .about("specify a tag to be applied-- may be given more than once")
                    .takes_value(true)
                    .multiple(true)
                    .number_of_values(1), // "-t a -t b...", not "-t a b..."
            )
            .arg(
                Arg::new("read-later")
                    .short('R')
                    .long("read-later")
                    .about("mark this pin as `read later'"),
            )
            .arg(
                Arg::new("title")
                    .short('T')
                    .long("title")
                    .about("link title")
                    .takes_value(true),
            )
            .arg(
                Arg::new("url")
                    .index(1)
                    .about("URL to be sent to pinboard.in")
                    .required(true),
            )
            .arg(
                Arg::new("instapaper")
                    .long("with-instapaper")
                    .short('i')
                    .about("Send this link to Instapaper as well"),
            )
            .arg(
                Arg::new("username")
                    .long("username")
                    .short('u')
                    .about("Your Instapaper username")
                    .takes_value(true),
            )
            .arg(
                Arg::new("password")
                    .long("password")
                    .short('p')
                    .about("Your Instapaper password")
                    .takes_value(true),
            ),
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                         The Big Kahuna                                         //
////////////////////////////////////////////////////////////////////////////////////////////////////

fn main() -> Result<(), Error> {
    use pin::vars::{AUTHOR, VERSION};

    let def_cfg = format!("{}/.pin", std::env::var("HOME")?);
    let mut app = App::new("pin")
        .version(VERSION)
        .author(AUTHOR)
        .about("Send links to Pinboard")
        .long_about("`pin' is a small utility for managing your Pinboard links.")
        .arg(
            Arg::new("config")
                .short('c')
                .about("specify a configuration file (defaults to ~/.pin")
                .takes_value(true)
                .value_name("FILE")
                .default_value(&def_cfg),
        )
        .arg(
            Arg::new("token")
                .short('t')
                .about("Your pinboard.in API token")
                .long_about(
                    "You can, at the time this help message was written, find your API key
at https://pinboard.in/settings/password.",
                )
                .takes_value(true),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .about("Enable verbose output"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .about("Enable very verbose output"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .about("Suppress all output other than errors"),
        );

    app = add_subcommands(app);
    let matches = app.get_matches();

    // Let us begin by configuring logging. `pin' does not log to traditional log file; rather, I
    // (ab)use the logging package to implement the various verbosity settings.
    let fl = match (
        matches.is_present("quiet"),
        matches.is_present("verbose"),
        matches.is_present("debug"),
    ) {
        (false, _, true) => LevelFilter::Trace,
        (false, true, false) => LevelFilter::Debug,
        (true, true, false) | (true, false, true) | (true, true, true) => {
            return Err(Error::BadVerbosity)
        }
        (true, false, false) => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let app = ConsoleAppender::builder()
        .target(Target::Stdout)
        .encoder(Box::new(PatternEncoder::new("{m}{n}")))
        .build();
    let lcfg = log4rs::config::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(app)))
        .build(Root::builder().appender("stdout").build(fl))
        .unwrap();
    log4rs::init_config(lcfg)?;

    trace!("logging configured.");
    // reading the confguration file, if present. The `config' option was given
    // a default value above, so this should be fine.
    let cfg_file = matches.value_of("config").context(NoConfig {})?;
    // One way or another, build ourselves a `Config' instance; from the user's configuration file
    // if possible...
    let mut cfg: Config = match std::fs::read_to_string(Path::new(&cfg_file)) {
        Ok(text) => toml::from_str(&text).context(ConfigRead { cfg_file })?,
        // or from scratch if not. But if the user explicitly specified a config file, and we
        // couldn't find it, they probably want to know about that.
        Err(err) => match (err.kind(), matches.occurrences_of("config")) {
            // They didn't specify a config file, and the default wasn't present. NBD, just
            // create a default configuration.
            (std::io::ErrorKind::NotFound, 0) => Config::new(),
            // They did specify a config file, and it wasn't found. Tell 'em:
            (std::io::ErrorKind::NotFound, _) => {
                return Err(Error::ConfigNotFound {
                    cfg_file: cfg_file.to_string(),
                });
            }
            // Urp?! Something else went wrong-- bail.
            (_, _) => {
                return Err(Error::from(err));
            }
        },
    };

    // The pinboard API token is taken, in order of precedence, from:
    //
    //     1. the command line
    //     2. the environment
    //     3. cfg
    //
    if let Some(token) = matches.value_of("token") {
        cfg.token = String::from(token);
    } else if let Ok(token) = std::env::var("PINBOARD_API_TOKEN") {
        cfg.token = token;
    }
    // One way or another, we need a token:
    if cfg.token.len() == 0 {
        return Err(Error::NoToken);
    }

    let mut cli = pin::pinboard::Client::new(cfg.token);

    if let Some(sub) = matches.subcommand_matches("get-tags") {
        let alpha = sub.is_present("alphabetical");
        let desc = sub.is_present("descending");
        let csv = sub.is_present("csv");
        Ok(get_tags(
            &mut std::io::stdout(),
            &mut cli,
            alpha,
            desc,
            csv,
        )?)
    } else if let Some(sub) = matches.subcommand_matches("rename-tag") {
        // `from' & `to' are marked as "required", so OK to call `unwrap' on 'em
        Ok(rename_tag(
            &mut std::io::stdout(),
            &mut cli,
            sub.value_of("from").unwrap(),
            sub.value_of("to").unwrap(),
        )?)
    } else if let Some(sub) = matches.subcommand_matches("send") {
        // `url' is marked as "required" so OK to call `unwrap' on it.
        let mut url = sub.value_of("url").unwrap().to_string();
        // `title' is required, but not marked as such. It may be given as an option (e.g.  "-t
        // my-title", or it may be given as part of the URL: "URL | TITLE". This is not only
        // convenient, it just happens to be the export format for OneTab
        let title = match sub.value_of("title") {
            Some(t) => t.to_string(),
            None => {
                let idx = url.find(" | ").context(NoTitle {})?;
                let t = url[idx + 3..].to_string();
                url = url[0..idx].to_string();
                t
            }
        };

        let (mut tags, mut rl, mut insty) = match sub.value_of("target") {
            Some(t) => {
                let target = cfg.targets.get(t).context(UnknownTarget { target: t })?;
                (target.tags.clone(), target.read_later, target.send_to_insty)
            }
            None => (vec![], false, false),
        };

        if let Some(vals) = sub.values_of("tag") {
            tags.append(&mut vals.map(|x| x.to_string()).collect());
        }

        if sub.is_present("read-later") {
            rl = true;
        }

        if sub.is_present("instapaper") {
            insty = true;
        }

        let mut insty_cli = if insty {
            if let Some(uname) = sub.value_of("username") {
                cfg.username = String::from(uname);
            } else if let Ok(uname) = std::env::var("PINBOARD_INSTAPAPER_USERNAME") {
                cfg.username = uname;
            }
            // One way or another, we need a token:
            if cfg.username.len() == 0 {
                return Err(Error::NoUsername);
            }

            if let Some(passw) = sub.value_of("password") {
                cfg.password = String::from(passw);
            } else if let Ok(passw) = std::env::var("PINBOARD_INSTAPAPER_PASSWORD") {
                cfg.password = passw;
            }
            // One way or another, we need a token:
            if cfg.password.len() == 0 {
                return Err(Error::NoPassword);
            }

            Some(pin::instapaper::Client::new(&cfg.username, &cfg.password))
        } else {
            None
        };

        Ok(send_link(
            &mut std::io::stdout(),
            &mut cli,
            insty_cli.as_mut(),
            &url,
            &title,
            rl,
            tags.iter().cloned(),
        )?)
    } else {
        Err(Error::NoSubCommand)
    }
}
