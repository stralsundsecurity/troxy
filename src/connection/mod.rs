use rustls::{ClientSession, ServerSession};

pub enum ProxySession {
    ClientSession(ClientSession),
    ServerSession(ServerSession),
}
