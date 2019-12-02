//! # troxy - the TLS proxy
//!
//! troxy is a TLS proxy written in Rust.
//! It is still in development.
//!
//! ## Features
//!
//! The goal is to support the following
//! features:
//!
//! * protocol independent TLS proxy
//! * simple CLI interface
//! * support for protocols like HTTP and others
//! * interception and manipulation of TLS connections
//! * extensibility
//!
//! ## Technology
//!
//! The TLS proxy is built on [rustls][1].
//! Some modules (including this)
//! are based on the rustls-mio examples.
//! See [rustls/rustls-mio][2].
//! The example code was authored by Joseph Birr-Pixton
//! and is distributed under the MIT license.
//!
//! [1]: https://github.com/ctz/rustls
//! [2]: https://github.com/ctz/rustls/tree/master/rustls-mio

use std::net::SocketAddr;

use mio::net::TcpListener;
use mio::Poll;

use crate::server::Endpoint;
use crate::server::ServerMode::{Http, Plain};
use clap::{App, Arg, SubCommand};

use log::{debug, warn};

pub mod client;
pub mod connection;
pub mod server;
pub mod token;

const LISTENER: mio::Token = mio::Token(0);

fn main() {
    env_logger::init();

    let matches = App::new("troxy")
        .version("0.1")
        .author("Viktor Garske <info@v-gar.de>")
        .about("TLS interception proxy")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .default_value("8080")
                .help("Sets the port to listen on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .value_name("ADDRESS")
                .default_value("0.0.0.0")
                .help("Sets the IP address to bind on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("certificate")
                .short("c")
                .long("cert")
                .value_name("FILE")
                .help("Sets the certifcate file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("privkey")
                .short("k")
                .long("key")
                .value_name("FILE")
                .help("Sets the private key file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("outputpath")
                .short("w")
                .long("output")
                .value_name("DIR")
                .help("Sets the output directory")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("dangerous")
                .long("dangerous")
                .help("Disables certificate verification on client side")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .help("Do not print hexdump output")
                .takes_value(false)
        )
        .subcommand(
            SubCommand::with_name("http")
                .about("http proxy")
                .version("0.1"),
        )
        .subcommand(
            SubCommand::with_name("plain")
                .about("plain connection")
                .arg(
                    Arg::with_name("dsthost")
                        .long("dsthost")
                        .value_name("HOST")
                        .takes_value(true)
                        .required(true)
                        .help("IP of the destination host."),
                )
                .arg(
                    Arg::with_name("dsthostname")
                        .long("dsthostname")
                        .value_name("HOSTNAME")
                        .takes_value(true)
                        .required(true)
                        .help("Name of the destination host. Must match the certificate name."),
                )
                .arg(
                    Arg::with_name("dstport")
                        .long("dstport")
                        .value_name("PORT")
                        .takes_value(true)
                        .required(true)
                        .help("Destination port"),
                ),
        )
        .get_matches();

    let bind = matches.value_of("bind").unwrap();
    let port = matches.value_of("port").unwrap();
    let cert_file = matches.value_of("certificate").unwrap();
    let privkey_file = matches.value_of("privkey").unwrap();

    let output_path;
    if let Some(output_path_str) = matches.value_of("outputpath") {
        output_path = Some(String::from(output_path_str));
    } else {
        output_path = None;
    }

    let dangerous = matches.is_present("dangerous");
    let quiet = matches.is_present("quiet");

    if dangerous {
        warn!("Certificate verification on client side disabled!");
    }

    let addr: SocketAddr = format!("{}:{}", bind, port).parse().unwrap();

    let listener = TcpListener::bind(&addr).expect("cannot bind on port");

    let mut poll = Poll::new().unwrap();

    poll.register(
        &listener,
        LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )
    .unwrap();

    let config = server::make_config(cert_file, privkey_file);

    // Prepare the server mode
    let mode: server::ServerMode;
    if let Some(sub_matches) = matches.subcommand_matches("plain") {
        let host = sub_matches.value_of("dsthost").unwrap();
        let port = sub_matches.value_of("dstport").unwrap();
        let hostname = sub_matches.value_of("dsthostname").unwrap();
        let dst: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
        mode = Plain(Endpoint {
            socketaddr: dst,
            hostname: String::from(hostname),
        });
    } else {
        mode = Http;
    }

    debug!("Mode: {:?}", mode);

    let mut tlsserver = server::TlsServer::new(mode, listener, config, output_path, dangerous,
    quiet);

    let mut events = mio::Events::with_capacity(256);

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            debug!("Master poll: processing event: {:?}", event);

            match event.token() {
                LISTENER => {
                    if !tlsserver.accept(&mut poll) {
                        break;
                    }
                }
                _ => tlsserver.conn_event(&mut poll, &event),
            }
        }
    }
}
