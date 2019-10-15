//! ## TLS server module
//!
//! This module provides the TLS server part for troxy.
//!
//! ### Source
//! The module is based on the rustls-mio examples of rustls.
//! See [rustls/rustls-mio][1].
//! The example code was authored by Joseph Birr-Pixton
//! and is distributed under the MIT license.
//!
//! [1]: https://github.com/ctz/rustls/tree/master/rustls-mio

use std::collections::HashMap;
use std::sync::Arc;

use std::fs;
use std::io::{BufReader, Read, Write};

use mio::net::{TcpListener, TcpStream};
use mio::Poll;
use std::net::Shutdown;

use rustls::{NoClientAuth, Session};

use crate::client;

use log::{debug, error, info, warn};

pub struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
}

impl TlsServer {
    pub fn new(server: TcpListener, config: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: config,
        }
    }

    pub fn accept(&mut self, poll: &mut Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                info!("Accepting connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);

                let token = mio::Token(self.next_id);
                self.next_id += 1;

                self.connections
                    .insert(token, Connection::new(socket, token, tls_session));
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                error!("error while accepting connection: {:?}", e);
                false
            }
        }
    }

    pub fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections.get_mut(&token).unwrap().ready(poll, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    tls_session: rustls::ServerSession,
    sent_http_response: bool,
}

impl Connection {
    fn new(socket: TcpStream, token: mio::Token, tls_session: rustls::ServerSession) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            sent_http_response: false,
        }
    }

    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let shutdown = self.socket.shutdown(Shutdown::Both);
            if shutdown.is_err() {
                error!("Error while shutting down connection");
            }
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    fn do_tls_read(&mut self) {
        let read = self.tls_session.read_tls(&mut self.socket);

        if read.is_err() {
            let err = read.unwrap_err();

            if let std::io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            error!("Read error: {:?}", err);
            self.closing = true;
            return;
        }

        if read.unwrap() == 0 {
            debug!("eof, closing connection");
            self.closing = true;
            return;
        }

        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            warn!("cannot proccess packet: {:?}", processed);

            self.do_tls_write_and_handle_error();

            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        let mut buffer = Vec::new();

        let read = self.tls_session.read_to_end(&mut buffer);

        if read.is_err() {
            debug!("Plaintext read failed: {:?}, closing connection", read);
            self.closing = true;
            return;
        }

        if !buffer.is_empty() {
            debug!("Plaintext read: {:?}", buffer.len());
            self.incoming_plaintext(&buffer);
        }
    }

    fn incoming_plaintext(&mut self, buffer: &[u8]) {
        debug!("{}", String::from_utf8(buffer.to_vec()).unwrap());
        self.process(buffer);
    }

    fn process(&mut self, buffer: &[u8]) {
        // process stuff
        let mut request = String::from_utf8(buffer.to_vec()).unwrap();
        request = request.replace("Connection: keep-alive", "Connection: close");
        request = request.replace(
            "Accept-Encoding: gzip, deflate, br",
            "Accept-Encoding: identity",
        );
        request = request.replace("Host: localhost:8080", "Host: blog.v-gar.de");
        let res = client::http_request("blog.v-gar.de", &request);
        if res.is_none() {
            return;
        }

        let res = res.unwrap();
        let resp = String::from_utf8(res).unwrap();
        let response = resp.as_bytes();

        if !self.sent_http_response {
            self.tls_session.write_all(response).unwrap();
            self.sent_http_response = true;
            self.tls_session.send_close_notify();
        }
    }

    fn tls_write(&mut self) -> std::io::Result<usize> {
        self.tls_session.write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let write = self.tls_write();

        if write.is_err() {
            error!("write failed: {:?}", write);
            self.closing = true;
            return;
        }
    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    fn event_set(&self) -> mio::Ready {
        let read = self.tls_session.wants_read();
        let write = self.tls_session.wants_write();

        if read && write {
            mio::Ready::readable() | mio::Ready::writable()
        } else if write {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

pub fn make_config(cert_file: &str, privkey_file: &str) -> Arc<rustls::ServerConfig> {
    let client_auth = NoClientAuth::new();

    let mut config = rustls::ServerConfig::new(client_auth);
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let certs = load_certs(cert_file);
    let privkey = load_private_key(privkey_file);
    let cert_setting = config.set_single_cert(certs, privkey);
    if cert_setting.is_err() {
        panic!("Certificate and private key could not be set");
    }

    let flag_proto: Vec<String> = Vec::new();
    config.set_protocols(
        &flag_proto
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>()[..],
    );

    Arc::new(config)
}
