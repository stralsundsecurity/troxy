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
use mio::{Poll, Token};
use std::net::{Shutdown, SocketAddr};

use rustls::{NoClientAuth, Session};

use crate::client;
use crate::connection;
use crate::token::SessionTokenGroup;

use crate::client::ClientConnection;
use crate::connection::ProxySession;
use log::{debug, error, info, warn};
use std::hash::Hash;
use mio_extras::channel::{channel, Receiver, Sender};

#[derive(Debug, Clone)]
pub enum ServerMode {
    Plain(Endpoint),
    Http,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub socketaddr: SocketAddr,
    pub hostname: String,
}

enum ProxyConnection {
    ServerConnection(ServerConnection),
    ClientConnection(ClientConnection),
}

/// Main TLS server struct
/// Will be constructed one time for
/// every server
pub struct TlsServer {
    mode: ServerMode,
    server: TcpListener,
    connections: HashMap<mio::Token, ProxyConnection>,
    rx_connections: HashMap<mio::Token, mio::Token>,
    next_id: u32,
    next_token_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
}

impl TlsServer {
    pub fn new(
        mode: ServerMode,
        server: TcpListener,
        config: Arc<rustls::ServerConfig>,
    ) -> TlsServer {
        TlsServer {
            mode,
            server,
            connections: HashMap::new(),
            rx_connections: HashMap::new(),
            next_id: 0,
            next_token_id: 2,
            tls_config: config,
        }
    }

    pub fn accept(&mut self, poll: &mut Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                info!("Accepting connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);

                // Prepare tokens
                let session_token_group = SessionTokenGroup::new_from_counter(
                    &mut self.next_token_id);

                // Create MPSC channels
                // Server sends to the Client
                // Client sends to the Server
                let (server_tx, client_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
                let (client_tx, server_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

                let (server_connection, client_connection) =
                    ServerConnection::new_with_client_connection(
                        self.next_id,
                        socket,
                        session_token_group.clone(),
                        tls_session,
                        self.mode.clone(),
                        server_tx,
                        server_rx,
                        Some(client_tx),
                        Some(client_rx)
                    );
                server_connection.register(poll);

                // Server token
                self.connections.insert(
                    session_token_group.server_connection.clone(),
                    ProxyConnection::ServerConnection(server_connection),
                );
                self.rx_connections.insert(
                    session_token_group.server_rx.clone(),
                    session_token_group.server_connection.clone()
                );

                // Client token
                if let Some(client_connection) = client_connection {
                    client_connection.register(poll);
                    self.connections.insert(
                        session_token_group.client_connection.clone(),
                        ProxyConnection::ClientConnection(client_connection),
                    );

                    self.rx_connections.insert(
                        session_token_group.client_rx.clone(),
                        session_token_group.client_connection.clone()
                    );
                }

                self.next_id += 1;
                true
            }

            Err(e) => {
                error!("error while accepting connection: {:?}", e);
                false
            }
        }
    }

    pub fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::Event) {
        let mut token = event.token();

        if self.rx_connections.contains_key(&token) {
            token = self.rx_connections[&token];
        }

        if self.connections.contains_key(&token) {
            let proxy_connection = self.connections.get_mut(&token).unwrap();

            let mut closed = false;
            match proxy_connection {
                ProxyConnection::ServerConnection(server) => {
                    server.ready(poll, event);
                    closed = server.closed;
                }
                ProxyConnection::ClientConnection(client) => {
                    client.ready(poll, event);
                }
                _ => unimplemented!(),
            }

            // remove old connections
            if closed {
                self.connections.remove(&token);
            }
        } else {
            debug!("Missing key!");
        }
    }
}

fn try_read(r: std::io::Result<usize>) -> std::io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

struct ServerConnection {
    id: u32,
    socket: TcpStream,

    session_token_group: SessionTokenGroup,

    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_session: rustls::ServerSession,
    sent_http_response: bool,

    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl ServerConnection {
    fn new(
        id: u32,
        socket: TcpStream,
        session_token_group: SessionTokenGroup,
        tls_session: rustls::ServerSession,
        mode: ServerMode,
        server_tx: Sender<Vec<u8>>,
        server_rx: Receiver<Vec<u8>>,
        client_tx: Sender<Vec<u8>>,
        client_rx: Receiver<Vec<u8>>,
    ) -> ServerConnection {
        let (server_connection, _): (ServerConnection, _) = Self::new_with_client_connection(
            id,
            socket,
            session_token_group,
            tls_session,
            mode,
            server_tx,
            server_rx,
            None,
            None,
        );

        server_connection
    }

    fn new_with_client_connection(
        id: u32,
        socket: TcpStream,
        session_token_group: SessionTokenGroup,
        tls_session: rustls::ServerSession,
        mode: ServerMode,
        server_tx: Sender<Vec<u8>>,
        server_rx: Receiver<Vec<u8>>,
        client_tx: Option<Sender<Vec<u8>>>,
        client_rx: Option<Receiver<Vec<u8>>>,
    ) -> (ServerConnection, Option<ClientConnection>) {
        let forwarded = Self::open_forwarded(
            id,
            &mode,
            client_tx,
            client_rx,
            session_token_group.clone()
        );

        (
            ServerConnection {
                id,
                socket,
                session_token_group,
                closing: false,
                closed: false,
                mode,
                tls_session,
                sent_http_response: false,
                tx: server_tx,
                rx: server_rx,
            },
            forwarded,
        )
    }

    fn open_forwarded(
        id: u32,
        mode: &ServerMode,
        tx: Option<Sender<Vec<u8>>>,
        rx: Option<Receiver<Vec<u8>>>,
        session_token_group: SessionTokenGroup
    ) -> Option<ClientConnection> {
        match *mode {
            ServerMode::Plain(ref endpoint) => {
                debug!(
                    "Setting up forwarded client connection to {:#}",
                    endpoint.socketaddr
                );
                let connection = ClientConnection::new(
                    id,
                    &endpoint.socketaddr,
                    &endpoint.hostname,
                    tx,
                    rx,
                    session_token_group,
                );
                debug!("Connection set up!");
                Some(connection)
            }
            _ => None,
        }
    }

    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        debug!("Ready called with poll {:?} and event {:?}", poll, ev);

        if ev.token() == self.session_token_group.server_connection {
            if ev.readiness().is_readable() {
                self.do_tls_read();
                self.try_plain_read();
            }

            if ev.readiness().is_writable() {
                // self.fetch_new_data();
                self.do_tls_write_and_handle_error();
            }
        } else if ev.token() == self.session_token_group.server_rx {
            if ev.readiness().is_readable() {
                self.fetch_new_data();
            }
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
        debug!("do_tls_read: read: {:?}", read);

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

        debug!("do_tls_read: call package processor");
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            warn!("cannot proccess packet: {:?}", processed);

            self.do_tls_write_and_handle_error();

            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        debug!("try_plain_read: try reading from plain");
        let mut buffer = Vec::new();

        debug!("try_plain_read: self.tls_session: {:?}", self.tls_session);
        let read = self.tls_session.read_to_end(&mut buffer);

        debug!("Finished reading from plain: {:?}", read);

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
        println!("Client -> Server");
        match String::from_utf8(buffer.to_vec()) {
            Ok(s) =>  println!("Plaintext: {}", s),
            Err(_) => println!("Plaintext: {:?}", buffer.to_vec())
        }

        match self.mode {
            ServerMode::Http => {
                self.process(buffer);
            }
            ServerMode::Plain(_) => {
                debug!("Sending {:?} to forwarded connetion...", buffer);
                self.tx.send(buffer.to_vec());
            }
        }
    }

    fn fetch_new_data(&mut self) {
        debug!("rx available, waiting for data");
        let msg = self.rx.try_recv();
        if msg.is_err() {
            debug!("No new rx info available");
            return;
        }
        let msg = msg.unwrap();
        debug!("MPSC data received: {:?}", msg);
        let res = self.tls_session.write_all(&msg).unwrap();
        debug!("Result: {:?}", res);
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
        // let res = client::http_request("blog.v-gar.de", &request);

        let mut connection = client::ClientConnection::new_by_hostname(
            self.id,
            "78.46.14.114",
            443,
            "blog.v-gar.de",
        );
        connection.write(&request.as_bytes());
        let res = None;

        if res.is_none() {
            return;
        }

        let res = res.unwrap();
        let resp = String::from_utf8(res).unwrap();
        let response = resp.as_bytes();

        if !self.sent_http_response {
            self.tls_session.write_all(response).unwrap();
            // self.sent_http_response = true;
            // self.tls_session.send_close_notify();
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

    /// Register the Client to Proxy connection
    fn register(&self, poll: &mut mio::Poll) {
        debug!(
            "Registering Client -> Proxy socket {:?} with token {:?}",
            self.socket, self.session_token_group.server_connection
        );
        poll.register(
            &self.socket,
            self.session_token_group.server_connection,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();

        poll.register(
            &self.rx,
            self.session_token_group.server_rx,
            mio::Ready::readable(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
            .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        debug!("Interest: {:?}", self.event_set());
        poll.reregister(
            &self.socket,
            self.session_token_group.server_connection,
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
