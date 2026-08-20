pub mod engine;
pub mod hasher;
pub mod incremental;
pub mod paths;
pub mod result;
pub mod targets;
pub mod walk;

pub use result::{DetectionKind, Finding, ScanResult, Verdict};
