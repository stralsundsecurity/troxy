# troxy - the TLS proxy
troxy is a TLS proxy written in Rust.
It is still in development.

## Features

The goal is to support the following 
features:

  * protocol independent TLS proxy
  * simple CLI interface
  * support for protocols like HTTP and others
  * interception and manipulation of TLS connections
  * extensibility

## Build

You need to install the latest version of [Rust][1].
Use [rustup][2] or use the proper package with rustc and cargo
for your distribution.

Create a wildcard certificate (FQDN *) in /tmp using[^1]

```bash
cd /tmp
openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

Then run:

```bash
cargo run
```

A proxy will be spawned on port 8080.

[^1]: This is only needed during early development phase.
[1]: https://www.rust-lang.org/
[2]: https://rustup.rs/
