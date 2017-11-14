extern crate webpki;
extern crate webpki_roots;
extern crate rustls;
extern crate ktls_poc;

use std::io::{ Read, Write, stdout };
use std::net::TcpStream;
use webpki::DNSNameRef;
use rustls::ClientConfig;
use ktls_poc::Stream;


fn main() {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name = DNSNameRef::try_from_ascii_str("github.com").unwrap();
    let mut sock = TcpStream::connect("github.com:443").unwrap();
    let mut tls = Stream::from_client_config(config, dns_name, sock);
    tls.write(concat!("GET / HTTP/1.1\r\n",
                      "Host: github.com\r\n",
                      "Connection: close\r\n",
                      "Accept-Encoding: identity\r\n",
                      "\r\n")
              .as_bytes())
        .unwrap();

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
