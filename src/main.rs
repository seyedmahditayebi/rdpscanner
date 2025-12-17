use anyhow::anyhow;
use clap::Parser;
use futures::stream::{self, StreamExt};
use indicatif::ProgressBar;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::thread;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    inputfile: PathBuf,

    #[arg(short, long, default_value_t = 100)]
    rate: usize,

    #[arg(short, long, default_value_t = 10)]
    timeout: u8,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Error, Debug)]
enum RdpError {
    #[error("response lenght is below 19 bytes")]
    ShortResponse,

    #[error("got neg failure response")]
    NegFailure,

    #[error("protocol is not rdp")]
    NonRdp,
}

#[rustfmt::skip]
const REQUEST: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, // TPKT (version 3, length 19)
    0x0e, // X.224 LI(Length Indicator)
    0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR TPDU
    // RDP_NEG_REQ 
    0x01, 0x00, // (type=1, flags=0)
    0x08, 0x00, // length=8
    0x0b, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
];

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut ips = File::open(cli.inputfile).expect("Can't read the file");
    let reader = BufReader::new(&ips);

    let mut line_number: u64 = 0;
    let reader_iter = reader.lines().map(|x| {
        line_number += 1;
        x.as_ref().unwrap().parse::<SocketAddrV4>().expect(
            format!(
                "Parse error at line {line_number}: \"{}\" Error",
                x.unwrap()
            )
            .as_str(),
        );
    });
    // consume the iterator to check if the file is valid
    for _ in reader_iter {}

    ips.seek(std::io::SeekFrom::Start(0)).unwrap();
    let reader = BufReader::new(&ips);

    let (tx, mut rx) = mpsc::channel(cli.rate);
    let handle = thread::spawn(move || {
        let mut pb = ProgressBar::new(line_number);
        if cli.verbose {
            pb = ProgressBar::hidden();
        }
        while let Some(update) = rx.blocking_recv() {
            if let Some(inner_value) = update {
                pb.suspend(|| {
                    println!("{inner_value}");
                })
            }
            pb.inc(1);
        }
        pb.finish();
    });

    stream::iter(reader.lines())
        .map(|ip| scan(ip.unwrap().parse().unwrap(), cli.timeout, cli.verbose))
        .buffer_unordered(cli.rate)
        .filter_map(|res| {
            let tx_clone = tx.clone();
            async move {
                if let Ok(value) = res {
                    tx_clone.send(Some(value)).await.unwrap();
                } else {
                    tx_clone.send(None).await.unwrap();
                }
                res.ok()
            }
        })
        .collect::<Vec<SocketAddrV4>>()
        .await;

    drop(tx);
    handle.join().unwrap();
}

async fn scan(
    socket: SocketAddrV4,
    time_out: u8,
    verbose: bool,
) -> Result<SocketAddrV4, anyhow::Error> {
    let mut stream = timeout(
        Duration::from_secs(time_out as u64),
        TcpStream::connect(&socket),
    )
    .await??;
    stream.set_nodelay(true).unwrap();
    let mut response = [0u8; 64];

    stream.write_all(REQUEST).await?;
    let bytes_read = timeout(
        Duration::from_secs(time_out as u64),
        stream.read(&mut response),
    )
    .await??;

    if verbose && bytes_read > 0 {
        eprintln!("bytes_read[{bytes_read}]:{socket}:{response:?}");
    }

    if bytes_read >= 19 {
        if response[0] == 0x03 && response[5] == 0xd0 {
            let neg_type = response[11];
            if neg_type == 0x02 {
                // RDP_NEG_RESPONSE
                return Ok(socket);
            } else if neg_type == 0x03 {
                // RDP_NEG_FAILURE
                match response[15] {
                    1 => {
                        // SSL_REQUIRED_BY_SERVER
                        return Ok(socket);
                    }
                    2 => {
                        // SSL_NOT_ALLOWED_BY_SERVER
                        return Ok(socket);
                    }
                    5 => {
                        // HYBRID_REQUIRED_BY_SERVER
                        return Ok(socket);
                    }
                    _ => {
                        if verbose {
                            eprintln!("Got neg failure on {socket}");
                        }
                        return Err(anyhow!(RdpError::NegFailure));
                    }
                };
            } else {
                Err(anyhow!(RdpError::NonRdp))
            }
        } else {
            Err(anyhow!(RdpError::NonRdp))
        }
    } else {
        Err(anyhow!(RdpError::ShortResponse))
    }
}
