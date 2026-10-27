//! Bounded SNMP polling, notification verification and shared alarm integration.
pub mod config;
pub mod engine;
pub mod hpe;
pub mod network;
pub mod persistence;
pub mod polling;
pub mod profiles;
pub mod records;
pub mod secrets;
mod synology;
pub mod transport;
mod ups;

pub mod notifications;
pub mod receipts;
pub mod receiver;

pub mod integration;
pub mod traps;
