use mio::net::TcpStream;
use mio::Token;
use rustls::{ClientSession, ServerSession};

pub enum ProxySession {
    ClientSession(ClientSession),
    ServerSession(ServerSession),
}
