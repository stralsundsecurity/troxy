use mio::Token;

#[derive(Clone, Debug)]
pub struct SessionTokenGroup {
    pub server_connection: Token,
    pub client_connection: Token,

    pub server_rx: Token,
    pub client_rx: Token
}

impl SessionTokenGroup {
    pub fn new_from_counter(next_token_id: &mut usize) -> SessionTokenGroup {
        let server_connection = Token(*next_token_id);
        *next_token_id += 1;

        let client_connection = Token(*next_token_id);
        *next_token_id += 1;

        let server_rx = Token(*next_token_id);
        *next_token_id += 1;

        let client_rx = Token(*next_token_id);
        *next_token_id += 1;

        SessionTokenGroup {
            server_connection,
            client_connection,

            server_rx,
            client_rx
        }
    }
}