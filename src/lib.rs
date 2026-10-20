pub mod api;
mod assessment;
pub mod collector;
pub mod dsm;
pub mod legacy_tls;
pub mod model;
pub mod store;
pub mod vault;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub mod identity;

pub mod mail;
pub mod mail_replay;

pub mod notification;

pub mod correlation;

pub mod archive;
pub mod history;

pub mod i18n;

pub mod acknowledgement;
