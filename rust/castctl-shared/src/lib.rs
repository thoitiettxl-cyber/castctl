//! History-event resource shaping, ported from Go
//! `internal/shared/resources.go` and `values.go` (M1, pure logic).

pub mod resources;
pub mod value;

pub use resources::{FileRow, Resource, event_resources, file_row_to_json, file_rows, local_name};
pub use value::JsonValue;
