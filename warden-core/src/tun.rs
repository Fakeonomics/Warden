use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[async_trait::async_trait]
pub trait Tun: Send {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

pub struct TunTap {
    dev: Option<tun::AsyncDevice>,
    name: String,
}

impl TunTap {
    pub fn new(name: &str) -> Self {
        Self {
            dev: None,
            name: name.to_string(),
        }
    }
}

impl Default for TunTap {
    fn default() -> Self {
        Self::new("warden0")
    }
}

impl AsyncRead for TunTap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match &mut self.dev {
            Some(dev) => Pin::new(dev).poll_read(cx, buf),
            None => Poll::Ready(Err(io::Error::other("tun not open"))),
        }
    }
}

impl AsyncWrite for TunTap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.dev {
            Some(dev) => Pin::new(dev).poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::other("tun not open"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.dev {
            Some(dev) => Pin::new(dev).poll_flush(cx),
            None => Poll::Ready(Err(io::Error::other("tun not open"))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn is_write_vectored(&self) -> bool {
        self.dev
            .as_ref()
            .map(|d| d.is_write_vectored())
            .unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl Tun for TunTap {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use tokio::io::AsyncReadExt;
        AsyncReadExt::read(self, buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        AsyncWriteExt::write(self, buf).await
    }

    fn name(&self) -> &str {
        &self.name
    }
}

pub async fn open_tun(name: &str) -> io::Result<TunTap> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config.address("10.66.66.2".parse::<std::net::Ipv4Addr>().unwrap());
    config.netmask("255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap());
    config.mtu(1280);
    config.up();

    let dev = tun::create_as_async(&config).map_err(io::Error::other)?;

    tracing::info!("tun device {} opened", name);
    Ok(TunTap {
        dev: Some(dev),
        name: name.to_string(),
    })
}

pub async fn try_open_tun() -> Option<TunTap> {
    match open_tun("warden0").await {
        Ok(dev) => Some(dev),
        Err(e) => {
            tracing::warn!("tun open failed (no root?): {}", e);
            None
        }
    }
}
