//! ## TLS client module
//!
//! This module provides the TLS client part of troxy.
//!
//! ### Source
//! The module is based on the rustls-mio examples of rustls.
//! See [rustls/rustls-mio][1].
//! The example code was authored by Joseph Birr-Pixton
//! and is distributed under the MIT license.
//!
//! [1]: https://github.com/ctz/rustls/tree/master/rustls-mio

use std::sync::Arc;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

use rustls;
use webpki;
use webpki_roots;

use rustls::Session;

use log::debug;

pub fn get_page(domain: &str, path: &str) -> Option<Vec<u8>> {
    let httpreq = format!(
        "GET {} HTTP/1.0\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\r\n",
        path, domain
    );
    http_request(domain, &httpreq)
}

pub fn http_request(domain: &str, httpreq: &str) -> Option<Vec<u8>> {
    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect(format!("{}:443", domain)).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    // Prepare the request
    tls.write_all(httpreq.as_bytes()).unwrap();

    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    debug!("Curr ciphersuite: {:?}", ciphersuite.suite);
    let mut plaintext = Vec::new();
    let res = tls.read_to_end(&mut plaintext);

    // if !plaintext.is_empty() {
    // stdout().write_all(&plaintext).unwrap();
    // }

    let _terminated;
    if res.is_err() {
        let err = res.unwrap_err();
        if err.kind() == ErrorKind::ConnectionAborted {
            // println!("Connection terminated successfully");
            _terminated = true;
            return Some(plaintext);
        } else {
            println!("Error happend: {}", err);
        }
    }

    None
}
