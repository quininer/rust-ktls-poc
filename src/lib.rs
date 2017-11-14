//! ref [ktls](https://github.com/torvalds/linux/blob/v4.13/Documentation/networking/tls.txt)


extern crate libc;
extern crate byteorder;
extern crate webpki;
extern crate rustls;

#[path = "uapi-tls.rs"]
pub mod uapi_tls;

use std::mem;
use std::io::{ self, Read, Write };
use std::os::unix::io::AsRawFd;
use std::net::TcpStream;
use std::sync::Arc;
use libc::setsockopt;
use byteorder::{ ByteOrder, LittleEndian };
use webpki::DNSNameRef;
use rustls::{ ALL_CIPHERSUITES, Session, ClientConfig, ClientSession };

use uapi_tls::{ TCP_ULP, SOL_TLS, TLS_TX, tls12_crypto_info_aes_gcm_128 };


pub unsafe fn ktls_start_send<Fd: AsRawFd>(socket: &mut Fd, info: &tls12_crypto_info_aes_gcm_128) -> io::Result<()> {
    let socket = socket.as_raw_fd();

    if setsockopt(socket, SOL_TLS, TCP_ULP, b"tls\0".as_ptr() as _, 4) != 0 {
        return Err(io::Error::last_os_error());
    }

    if setsockopt(socket, SOL_TLS, TLS_TX as _, info as *const _ as _, mem::size_of::<tls12_crypto_info_aes_gcm_128>() as _) != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}



pub struct Stream<S> {
    sess: S,
    sock: TcpStream
}

impl Stream<ClientSession> {
    pub fn from_client_config(mut config: ClientConfig, name: DNSNameRef, sock: TcpStream) -> Self {
        config.ciphersuites.clear();
        config.ciphersuites.push(ALL_CIPHERSUITES[2]);
        config.ciphersuites.push(ALL_CIPHERSUITES[6]);
        config.ciphersuites.push(ALL_CIPHERSUITES[8]);
        Self::new(ClientSession::new(&Arc::new(config), name), sock)
    }
}

impl<S: Session> Stream<S> {
    pub fn new(sess: S, sock: TcpStream) -> Self {
        Stream { sess, sock }
    }

    fn handshake(&mut self) -> io::Result<()> {
        if self.sess.is_handshaking() {
            self.sess.complete_io(&mut self.sock)?;

            if let Some(secrets) = self.sess.get_secrets() {
                let scs = self.sess.get_suite();
                assert_eq!(scs.enc_key_len, uapi_tls::TLS_CIPHER_AES_GCM_128_KEY_SIZE as _);

                let key_block = secrets.make_key_block(scs.key_block_len());
                let mut crypto_info = tls12_crypto_info_aes_gcm_128::default();

                let (read_seq, write_seq) = self.sess.get_seq();
                let (client_key, remaining) = key_block.split_at(scs.enc_key_len);
                let (server_key, remaining) = remaining.split_at(scs.enc_key_len);
                let (client_iv, remaining) = remaining.split_at(scs.fixed_iv_len);
                let (server_iv, remaining) = remaining.split_at(scs.fixed_iv_len);
                let (explicit_nonce_offs, _) = remaining.split_at(scs.explicit_nonce_len);

                // TODO
                // seq/rec_seq

                if secrets.randoms.we_are_client {
                    crypto_info.key.copy_from_slice(client_key);
                    crypto_info.salt.copy_from_slice(client_iv);
                    LittleEndian::write_u64(&mut crypto_info.iv, write_seq);
                    LittleEndian::write_u64(&mut crypto_info.rec_seq, write_seq);
                } else {
                    crypto_info.key.copy_from_slice(server_key);
                    crypto_info.salt.copy_from_slice(server_iv);
                    LittleEndian::write_u64(&mut crypto_info.iv, read_seq);
                }

                unsafe {
                    ktls_start_send(&mut self.sock, &crypto_info)?;
                }
            }
        }

        Ok(())
    }
}

impl<S: Session> Read for Stream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshake()?;

        if self.sess.wants_read() {
            self.sess.complete_io(&mut self.sock)?;
        }

        self.sess.read(buf)
    }
}

impl<S: Session> Write for Stream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshake()?;

        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}
