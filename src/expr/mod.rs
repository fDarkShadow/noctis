mod rhai;
mod template;

pub use rhai::{eval_condition, eval_script};
pub use template::{interpolate, interpolate_lenient};
