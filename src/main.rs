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

use clap::{Arg, App};

pub mod client;
pub mod server;

const LISTENER: mio::Token = mio::Token(0);

fn main() {
    env_logger::init();

    let matches = App::new("troxy")
        .version("0.1")
        .author("Viktor Garske <info@v-gar.de>")
        .about("TLS interception proxy")
        .arg(Arg::with_name("port")
             .short("p")
             .long("port")
             .value_name("PORT")
             .default_value("8080")
             .help("Sets the port to listen on")
             .takes_value(true))
        .arg(Arg::with_name("bind")
             .short("b")
             .long("bind")
             .value_name("ADDRESS")
             .default_value("0.0.0.0")
             .help("Sets the IP address to bind on")
             .takes_value(true))
        .arg(Arg::with_name("certificate")
             .short("c")
             .long("cert")
             .value_name("FILE")
             .help("Sets the certifcate file")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("privkey")
             .short("k")
             .long("key")
             .value_name("FILE")
             .help("Sets the private key file")
             .takes_value(true)
             .required(true))
        .get_matches();


    let bind = matches.value_of("bind").unwrap();
    let port = matches.value_of("port").unwrap();
    let cert_file = matches.value_of("certificate").unwrap();
    let privkey_file = matches.value_of("privkey").unwrap();

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

    let mut tlsserver = server::TlsServer::new(listener, config);

    let mut events = mio::Events::with_capacity(256);

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
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
