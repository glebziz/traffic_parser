use crate::app::App;
use crate::errors::Error;

mod app;
mod config;
mod connection;
mod detector;
mod domain_watcher;
mod errors;
mod http;
mod interface;
mod nft;
mod packet;
mod processor;

#[tokio::main]
async fn main() {
    let app = match App::new() {
        Ok(app) => app,
        Err(err) => fatal(err),
    };

    if let Err(err) = app.run() {
        fatal(err);
    }
}

fn fatal(err: Error) -> ! {
    eprintln!("{err}");
    std::process::exit(1);
}
