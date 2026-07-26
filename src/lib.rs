#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
// Panic-free policy for library code: the crate ingests untrusted SQL, so a
// panic is a robustness bug. Scoped to the non-test build of this crate;
// unit tests (`cfg(test)`) and the separate integration-test crates keep the
// ergonomic `unwrap`/`expect`.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;

/// Re-exports of `alloc` types and macros that live in the `std` prelude but
/// not the `core` prelude, so modules can `use crate::no_std_prelude::*` and
/// compile in both `std` and `no_std` builds.
#[cfg(not(feature = "std"))]
pub(crate) mod no_std_prelude {
    pub(crate) use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

/// RLS expression classification: pattern matching, function registry, and confidence scoring.
pub mod classifier;
/// `OpenFGA` model generation from classified policies (DSL, JSON, and tuple SQL).
pub mod generator;
/// File output and markdown report generation.
pub mod output;
/// SQL schema parsing and function body analysis.
pub mod parser;
/// High-level builder/facade for classification and `OpenFGA` translation.
pub mod translator;
