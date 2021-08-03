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

//! Module housing the [`error_from`] macro.

/// Implement [`From`] for a given error type for the local Error type.
///
/// Sometimes I just want to convert from another module's error type ([`std::io::Error`], say)
/// to my own, without having to provide [Snafu](https://github.com/shepmaster/snafu) context.
/// This macro will implement [`From`] that error type to the local,
/// [Snafu](https://github.com/shepmaster/snafu)-based error.
///
/// The local error type must be named "Error", it's associated value type must be a struct named
/// "Other" and have two members: "cause" and "back" (of types `Box<dyn Error>` and `Backtrace`
/// respectively). Not very re-usable but it's my first Rust macro.
///
/// [`From`]: [`std::convert::From`]
/// [`std::io::Error`]: [`std::io::From`]
#[macro_export]
macro_rules! error_from {
    ($t:ty) => {
        impl std::convert::From<$t> for Error {
            fn from(err: $t) -> Self {
                Error::Other {
                    cause: Box::new(err),
                    back: Backtrace::generate(),
                }
            }
        }
    };
}
