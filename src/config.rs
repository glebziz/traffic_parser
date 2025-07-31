use crate::errors::Error;
use serde::Deserialize;
use std::time;

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
    pub table: Table,
    #[serde(default)]
    pub capture: Capture,
    #[serde(default)]
    pub detector: Detector,
    #[serde(default)]
    pub debug: Debug,
}

#[derive(Deserialize, Debug)]
pub struct Table {
    #[serde(default = "Table::default_name")]
    pub name: String,
    #[serde(default = "Table::default_family")]
    pub family: String,
    #[serde(default = "Table::default_set")]
    pub detector_set: String,
    #[serde(default = "Table::default_v6_set")]
    pub detector_v6_set: String,
}

impl Default for Table {
    fn default() -> Table {
        Table {
            name: Self::default_name(),
            family: Self::default_family(),
            detector_set: Self::default_set(),
            detector_v6_set: Self::default_v6_set(),
        }
    }
}

impl Table {
    fn default_name() -> String {
        "fw".to_string()
    }

    fn default_family() -> String {
        "inet".to_string()
    }

    fn default_set() -> String {
        "detector".to_string()
    }

    fn default_v6_set() -> String {
        "detector_v6".to_string()
    }
}

#[derive(Deserialize, Debug)]
pub struct Capture {
    #[serde(default = "Capture::default_interface")]
    pub interface: String,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default = "Capture::default_size")]
    pub capture_size: i32,
    #[serde(
        default = "Capture::default_timeout",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub timeout: time::Duration,
}

impl Default for Capture {
    fn default() -> Capture {
        Capture {
            interface: Self::default_interface(),
            filter: None,
            capture_size: Self::default_size(),
            timeout: Self::default_timeout(),
        }
    }
}

impl Capture {
    fn default_interface() -> String {
        "eth0".to_string()
    }

    fn default_size() -> i32 {
        2048
    }

    fn default_timeout() -> time::Duration {
        time::Duration::from_secs(1)
    }
}

#[derive(Deserialize, Debug)]
pub struct Detector {
    #[serde(default = "Detector::default_detector_count")]
    pub detector_count: u8,
    #[serde(
        default = "Detector::default_conn_ttl",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub conn_ttl: time::Duration,
}

impl Default for Detector {
    fn default() -> Detector {
        Detector {
            detector_count: Self::default_detector_count(),
            conn_ttl: Self::default_conn_ttl(),
        }
    }
}

impl Detector {
    fn default_detector_count() -> u8 {
        3
    }

    fn default_conn_ttl() -> time::Duration {
        time::Duration::from_secs(60)
    }
}

#[derive(Deserialize, Debug)]
pub struct Debug {
    #[serde(default = "Debug::default_port")]
    pub port: u16,
}

impl Default for Debug {
    fn default() -> Debug {
        Debug {
            port: Self::default_port(),
        }
    }
}

impl Debug {
    fn default_port() -> u16 {
        55555
    }
}

impl Config {
    pub fn new(file: String) -> Result<Config, Error> {
        let cfg = match config::Config::builder()
            .add_source(config::File::with_name(&file))
            .build()
        {
            Ok(cfg) => cfg,
            Err(err) => return Err(Error::External(err.to_string())),
        };

        match cfg.try_deserialize::<Config>() {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(Error::External(err.to_string())),
        }
    }
}
