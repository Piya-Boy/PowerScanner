use crate::error::PsResult;
use crate::scan::ScanResult;

pub trait ResultSink {
    fn write(&mut self, result: &ScanResult) -> PsResult<()>;
}

pub mod jsonl;

pub use jsonl::{create as create_jsonl_sink, verify_file as verify_jsonl_file, JsonlSink};
