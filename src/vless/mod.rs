mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use types::{VlessAddress, VlessId, VlessTarget};
pub use wire::{read_request, read_response, write_request, write_response};
