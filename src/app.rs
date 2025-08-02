use crate::config;
use crate::config::Config;
use crate::connection::ConnTrack;
use crate::detector::Detector;
use crate::domain_watcher::DomainWatcher;
use crate::errors::Error;
use crate::http::Server;
use crate::interface::Interface;
use crate::nft::{Connection, IpSet, Table, TableFamily};
use crate::processor::Processor;
use clap::Parser;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::sync::Arc;

struct Nft {
    table: Table,
    detector_set: IpSet,
    detector_v6_set: IpSet,
    watcher_set: IpSet,
    watcher_v6_set: IpSet,
}

pub struct App {
    cfg: config::Detector,
    domains_file: String,

    conn: Connection,
    nft: Nft,

    iface: Interface,
    conn_track: Arc<ConnTrack>,

    server: Option<Server>,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(short, long, help = "Enable debug mode", default_value = "false")]
    debug: bool,
    #[arg(short, long, help = "Config file path", default_value = "config.yaml")]
    config: String,
}

impl App {
    pub fn new() -> Result<App, Error> {
        env_logger::init();
        let args = Arguments::parse();

        let cfg = Config::new(args.config)?;
        let (conn, nft) = App::init_nft(cfg.table)?;
        let iface = App::init_iface(cfg.capture)?;
        let conn_track = Arc::new(ConnTrack::new());

        let server = match args.debug {
            true => Some(Server::new(cfg.debug.port, conn_track.clone())),
            false => None,
        };

        Ok(App {
            cfg: cfg.detector,
            domains_file: cfg.domains_file,
            conn,
            nft,
            iface,
            conn_track,
            server,
        })
    }

    pub fn run(self) -> Result<(), Error> {
        if let Some(server) = self.server {
            tokio::spawn(server.run());
        }

        let detector = Detector::new(
            self.cfg,
            &self.conn,
            self.conn_track,
            |ip| self.iface.is_local(ip),
            &self.nft.table,
            &self.nft.detector_set,
            &self.nft.detector_v6_set,
        );

        let domains = App::load_domains(self.domains_file)?;
        let host_watcher = DomainWatcher::new(
            domains,
            &self.conn,
            &self.nft.table,
            &self.nft.watcher_set,
            &self.nft.watcher_v6_set,
        );

        let mut processor = Processor::new();
        processor.add_processor(&detector);
        processor.add_processor(&host_watcher);

        match self
            .iface
            .open()?
            .for_each(None, |p| processor.process(p.data))
        {
            Ok(()) => Ok(()),
            Err(err) => Err(Error::External(err.to_string())),
        }
    }

    fn init_nft(cfg: config::Table) -> Result<(Connection, Nft), Error> {
        let family = TableFamily::try_from(cfg.family)?;
        let table = Table::new(cfg.name, family);
        let detector_set = IpSet::new(cfg.detector_set);
        let detector_v6_set = IpSet::new(cfg.detector_v6_set);
        let watcher_set = IpSet::new(cfg.watcher_set);
        let watcher_v6_set = IpSet::new(cfg.watcher_v6_set);

        let mut conn = Connection::new()?;
        conn.check_table(&table)?;
        conn.check_ipset(&table, &detector_set)?;
        conn.check_ipset(&table, &detector_v6_set)?;
        conn.check_ipset(&table, &watcher_set)?;
        conn.check_ipset(&table, &watcher_v6_set)?;

        Ok((
            conn,
            Nft {
                table,
                detector_set,
                detector_v6_set,
                watcher_set,
                watcher_v6_set,
            },
        ))
    }

    fn init_iface(cfg: config::Capture) -> Result<Interface, Error> {
        let iface = Interface::find(cfg.interface)?;

        let iface = iface
            .set_pkt_size(cfg.capture_size)
            .set_timeout(cfg.timeout);

        match cfg.filter {
            Some(filter) => Ok(iface.set_filter(filter)),
            None => Ok(iface),
        }
    }

    fn load_domains(domains_file: String) -> Result<Vec<String>, Error> {
        let file = match File::open(domains_file) {
            Ok(file) => file,
            Err(err) => return Err(Error::External(err.to_string())),
        };

        let mut domains = Vec::new();
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(err) => return Err(Error::External(err.to_string())),
            };

            if line.is_empty() {
                continue;
            }

            domains.push(line);
        }

        Ok(domains)
    }
}
