use crate::config;
use crate::config::Config;
use crate::connection::ConnTrack;
use crate::detector::Detector;
use crate::errors::Error;
use crate::http::Server;
use crate::interface::Interface;
use crate::nft::{Connection, IpSet, Table, TableFamily};
use crate::processor::Processor;
use clap::Parser;
use std::sync::Arc;

pub struct App {
    cfg: config::Detector,

    conn: Connection,
    table: Table,
    detector_set: IpSet,
    detector_v6_set: IpSet,

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
        let (conn, table, detector_set, detector_v6_set) = App::init_nft(cfg.table)?;
        let iface = App::init_iface(cfg.capture)?;
        let conn_track = Arc::new(ConnTrack::new());

        let server = match args.debug {
            true => Some(Server::new(cfg.debug.port, conn_track.clone())),
            false => None,
        };

        Ok(App {
            cfg: cfg.detector,
            conn,
            table,
            detector_set,
            detector_v6_set,
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
            self.conn,
            self.conn_track,
            |ip| self.iface.is_local(ip),
            self.table,
            self.detector_set,
            self.detector_v6_set,
        );

        let mut processor = Processor::new();
        processor.add_processor(&detector);

        match self
            .iface
            .open()?
            .for_each(None, |p| processor.process(p.data))
        {
            Ok(()) => Ok(()),
            Err(err) => Err(Error::External(err.to_string())),
        }
    }

    fn init_nft(cfg: config::Table) -> Result<(Connection, Table, IpSet, IpSet), Error> {
        let family = TableFamily::try_from(cfg.family)?;
        let table = Table::new(cfg.name, family);
        let detector_set = IpSet::new(cfg.detector_set);
        let detector_v6_set = IpSet::new(cfg.detector_v6_set);

        let mut conn = Connection::new()?;
        conn.check_table(&table)?;
        conn.check_ipset(&table, &detector_set)?;
        conn.check_ipset(&table, &detector_v6_set)?;

        Ok((conn, table, detector_set, detector_v6_set))
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
}
