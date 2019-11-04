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

use mio_extras::channel::{Receiver, Sender};
use std::sync::Arc;

use mio::net::TcpStream;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr};

use rustls;
use webpki;
use webpki_roots;

use rustls::{ClientSession, Session};

use pretty_hex::pretty_hex;

use log::{debug, error};

use crate::token::SessionTokenGroup;
use std::io;

pub struct ClientConnection {
    _id: u32,
    socket: TcpStream,
    tls_session: ClientSession,

    closing: bool,
    pub closed: bool,

    tx: Option<Sender<Vec<u8>>>,
    rx: Option<Receiver<Vec<u8>>>,

    session_token_group: SessionTokenGroup,
}

impl ClientConnection {
    pub fn new(
        _id: u32,
        socketaddr: &SocketAddr,
        hostname: &str,
        tx: Option<Sender<Vec<u8>>>,
        rx: Option<Receiver<Vec<u8>>>,
        session_token_group: SessionTokenGroup,
        dangerous: bool,
    ) -> ClientConnection {
        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        if dangerous {
            apply_dangerous_options(&mut config);
        }

        let dns_name = webpki::DNSNameRef::try_from_ascii_str(hostname).unwrap();
        let sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
        let sock = TcpStream::connect(socketaddr).unwrap();

        debug!("Client session: {:?}", sess);
        debug!("Client token: {:?}", session_token_group);

        ClientConnection {
            _id,
            socket: sock,
            tls_session: sess,
            closing: false,
            closed: false,
            tx,
            rx,
            session_token_group,
        }
    }

    pub fn new_by_hostname(_id: u32, ip: &str, port: u16, hostname: &str) -> ClientConnection {
        let socketaddr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        // TODO: remove
        Self::new(
            _id,
            &socketaddr,
            hostname,
            None,
            None,
            SessionTokenGroup::new_from_counter(&mut 1),
            false,
        )
    }

    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self.tls_session.read_tls(&mut self.socket);
        debug!("READ TLS: {:?}", rc);
        if rc.is_err() {
            let error = rc.unwrap_err();
            if error.kind() == io::ErrorKind::WouldBlock {
                return;
            }
            println!("TLS read error: {:?}", error);
            self.close();
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.close();
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();

        debug!("Proccess result: {:?}", processed);

        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.close();
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

            println!("Server -> Proxy");
            println!("{}\n", pretty_hex(&buffer));

            if let Some(tx) = self.tx.as_mut() {
                let tx_result = tx.send(buffer.to_vec());
                match tx_result {
                    Err(e) => error!("MPSC channel error {}", e),
                    _ => {}
                }
            }
        }
    }

    pub fn close(&mut self) -> bool {
        self.closing = true;
        let shutdown_result = self.socket.shutdown(Shutdown::Both);
        match shutdown_result {
            Err(e) => {
                error!("Shutdown error: {}", e);
            }
            _ => {}
        }
        self.closed = true;

        true
    }

    /// Register the Proxy to Server connection
    pub fn register(&self, poll: &mut mio::Poll) {
        debug!(
            "Registering proxy -> server socket {:?} with token {:?} and event set {:?}",
            self.socket,
            self.session_token_group.client_connection,
            self.event_set()
        );
        poll.register(
            &self.socket,
            self.session_token_group.client_connection,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();

        if let Some(rx) = self.rx.as_ref() {
            poll.register(
                rx,
                self.session_token_group.client_rx,
                mio::Ready::readable(),
                mio::PollOpt::level() | mio::PollOpt::oneshot(),
            )
            .unwrap();
        }
    }

    pub fn reregister(&self, poll: &mut mio::Poll) {
        debug!(
            "REregistering proxy -> server socket {:?} with token {:?} and event set {:?}",
            self.socket,
            self.session_token_group.client_connection,
            self.event_set()
        );
        poll.reregister(
            &self.socket,
            self.session_token_group.client_connection,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    pub fn deregister(&self, poll: &mut mio::Poll) {
        if let Some(rx) = self.rx.as_ref() {
            match poll.deregister(rx) {
                Err(e) => {
                    error!("Error while deregistering: {}", e);
                }
                _ => {}
            }
        }
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

    pub fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        debug!("Ready called with poll {:?} and event {:?}", poll, ev);
        debug!("ev.token(): {:?}", ev.token());

        if ev.token() == self.session_token_group.client_connection {
            if ev.readiness().is_readable() {
                debug!("Readable client connection!");
                self.do_read();
                self.try_plain_read();
            }

            if ev.readiness().is_writable() {
                // write to socket
                debug!("Writable client connection!");
                // self.fetch_new_data();
                self.do_tls_write();
            }
        } else if ev.token() == self.session_token_group.client_rx {
            if ev.readiness().is_readable() {
                self.fetch_new_data();
            }
        }

        if !self.closed {
            self.reregister(poll);
        } else {
            self.deregister(poll);
        }
    }

    fn fetch_new_data(&mut self) {
        if let Some(rx) = self.rx.as_ref() {
            debug!("rx available, waiting for data");
            let msg = rx.try_recv();
            if msg.is_err() {
                match msg.unwrap_err() {
                    std::sync::mpsc::TryRecvError::Disconnected => {
                        self.close();
                    }
                    _ => {}
                }
                return;
            }
            let msg = msg.unwrap();
            debug!("MPSC data received: {:?}", msg);
            debug!(
                "MPSC data decoded: {}",
                String::from_utf8(msg.clone()).unwrap()
            );
            let res = self.write_all(&msg).unwrap();
            debug!("Result: {:?}", res);
        } else {
            debug!("No rx available");
        }
    }

    fn do_tls_write(&mut self) {
        let write_result = self.tls_session.write_tls(&mut self.socket);
        match write_result {
            Err(e) => error!("Error while writing to TLS session: {}", e),
            _ => {}
        }
    }
}

impl io::Write for ClientConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        debug!("Writing bytes to TLS session");
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for ClientConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

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

mod danger {
    use super::rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

fn apply_dangerous_options(cfg: &mut rustls::ClientConfig) {
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
}

pub fn http_request(domain: &str, httpreq: &str) -> Option<Vec<u8>> {
    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let addr: SocketAddr = format!("{}:443", domain).parse().unwrap();
    let mut sock = TcpStream::connect(&addr).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    // Prepare the request
    tls.write_all(httpreq.as_bytes()).unwrap();

    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    debug!("Curr ciphersuite: {:?}", ciphersuite.suite);
    let mut plaintext = Vec::new();
    let res = tls.read_to_end(&mut plaintext);

    debug!("Finalized reading to end");
    debug!("{:?}", res);

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
            println!("Error happened: {}", err);
        }
    }

    None
}
