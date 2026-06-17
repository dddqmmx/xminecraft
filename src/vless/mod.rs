mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use types::{VlessId, VlessTarget, VlessAddress};
pub use wire::{read_request, read_response, write_request, write_response};
