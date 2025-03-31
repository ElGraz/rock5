mod config;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::{BytesMut, BufMut}; // Add bytes crate for easier buffer handling
use ctrlc;

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const CONNECT_COMMAND: u8 = 0x01;
const RSV: u8 = 0x00; // Reserved byte

// Address Type constants
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN_NAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply Field constants
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
// Add other reply codes as needed (e.g., connection refused, network unreachable)


fn setup_signals(){
    let res = ctrlc::set_handler(move || {
        println!("Terminating.");
        std::process::exit(1) 
    });

    if res.is_err(){
        panic!("{res:?}")
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut cfg = config::get_config();

    setup_signals();
    let list_addr: String = cfg.get_host_str();
    println!(" -> Listening on {list_addr:?}");

    let listener = TcpListener::bind(list_addr).await?;
    
    loop {
        let (client_stream, client_addr) = listener.accept().await?;
        println!(" -> Accepted connection from: {}", client_addr);

        // Spawn a new asynchronous task to handle each client connection
        tokio::spawn(async move {
            if let Err(e) = handle_client(client_stream, client_addr).await {
                eprintln!("Error handling client {}: {}", client_addr, e);
            }
        });
    }
}

async fn handle_client(mut client_stream: TcpStream, client_addr: SocketAddr) -> io::Result<()> {
    // --- Stage 1: Method Selection ---
    // Read the client's method selection message
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let mut handshake_buf = [0u8; 2]; // Buffer for VER and NMETHODS
    client_stream.read_exact(&mut handshake_buf).await?;

    // Check SOCKS version
    if handshake_buf[0] != SOCKS_VERSION {
        eprintln!("Client {} sent unsupported SOCKS version: {}", client_addr, handshake_buf[0]);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported SOCKS version"));
    }

    let nmethods = handshake_buf[1] as usize;
    if nmethods == 0 {
         eprintln!("Client {} sent zero methods", client_addr);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No methods offered"));
    }
    let mut methods_buf = vec![0u8; nmethods];
    client_stream.read_exact(&mut methods_buf).await?;

    // Check if "No Authentication Required" (0x00) is supported by the client
    if !methods_buf.contains(&NO_AUTHENTICATION_REQUIRED) {
        eprintln!("Client {} does not support 'No Authentication Required'", client_addr);
        // Send response: Version 5, Method 0xFF (No acceptable methods)
        client_stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "No supported authentication method"));
    }

    // Send server method selection response: Version 5, Method 0x00
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    client_stream.write_all(&[SOCKS_VERSION, NO_AUTHENTICATION_REQUIRED]).await?;

    // --- Stage 2: Connection Request ---
    // Read the client's connection request message
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let mut request_header = [0u8; 4]; // VER, CMD, RSV, ATYP
    client_stream.read_exact(&mut request_header).await?;

    // Check SOCKS version again (though unlikely to change)
    if request_header[0] != SOCKS_VERSION {
         eprintln!("Client {} sent invalid SOCKS version in request: {}", client_addr, request_header[0]);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version in request"));
    }

    // Check reserved byte
    if request_header[2] != RSV {
         eprintln!("Client {} sent non-zero RSV byte: {}", client_addr, request_header[2]);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Non-zero RSV byte"));
    }

    // Only support CONNECT command for now
    if request_header[1] != CONNECT_COMMAND {
         eprintln!("Client {} requested unsupported command: {}", client_addr, request_header[1]);
         // Send failure reply
         send_reply(&mut client_stream, REP_GENERAL_FAILURE, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "Unsupported command"));
    }

    let atyp = request_header[3];
    let target_addr: String;
    let target_port: u16;

    // Parse DST.ADDR based on ATYP
    match atyp {
        ATYP_IPV4 => {
            // Read 4 bytes for IPv4 address
            let mut addr_buf = [0u8; 4];
            client_stream.read_exact(&mut addr_buf).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(addr_buf));
            target_addr = ip.to_string();
        }
        ATYP_DOMAIN_NAME => {
            // Read 1 byte for domain name length
            let mut len_buf = [0u8; 1];
            client_stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            // Read `len` bytes for domain name
            let mut domain_buf = vec![0u8; len];
            client_stream.read_exact(&mut domain_buf).await?;
            target_addr = String::from_utf8_lossy(&domain_buf).to_string();
        }
         ATYP_IPV6 => {
            // Read 16 bytes for IPv6 address
            let mut addr_buf = [0u8; 16];
            client_stream.read_exact(&mut addr_buf).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(addr_buf));
            target_addr = format!("[{}]", ip); // Format IPv6 correctly
        }
        _ => {
            eprintln!("Client {} sent unsupported address type: {}", client_addr, atyp);
            send_reply(&mut client_stream, REP_GENERAL_FAILURE, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported address type"));
        }
    }
    // Read 2 bytes for port
    let mut port_buf = [0u8; 2];
    client_stream.read_exact(&mut port_buf).await?;
    target_port = u16::from_be_bytes(port_buf);
    println!("Client {} requested connection to Domain: {}:{}", client_addr, target_addr, target_port);

    // --- Stage 3: Establish Connection to Target ---
    let target_socket_addr = match tokio::net::lookup_host(format!("{}:{}", target_addr, target_port)).await?.next() {
         Some(addr) => addr,
         None => {
             eprintln!("Could not resolve target address: {}:{}", target_addr, target_port);
             send_reply(&mut client_stream, REP_GENERAL_FAILURE, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
             return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Could not resolve target address"));
         }
     };


    println!("Connecting to target: {}", target_socket_addr);
    let mut target_stream = match TcpStream::connect(target_socket_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to connect to target {}: {}", target_socket_addr, e);
            // Determine appropriate reply code based on the error kind
            let rep_code = match e.kind() {
                io::ErrorKind::ConnectionRefused => 0x05, // Connection refused
                io::ErrorKind::AddrNotAvailable => 0x04, // Host unreachable (approximated)
                io::ErrorKind::TimedOut => 0x06, // TTL expired (approximated)
                _ => REP_GENERAL_FAILURE, // General SOCKS server failure
            };
            send_reply(&mut client_stream, rep_code, target_socket_addr).await?;
            return Err(e);
        }
    };
    println!("Successfully connected to target: {}", target_socket_addr);

    // --- Stage 4: Send Success Reply to Client ---
    // Get the local address the proxy used to connect to the target
    let bind_addr = target_stream.local_addr()?;
    send_reply(&mut client_stream, REP_SUCCEEDED, bind_addr).await?;
    println!("Sent success reply to client {}", client_addr);

    // --- Stage 5: Relay Data ---
    println!("Relaying data between {} and {}", client_addr, target_socket_addr);

    // Use copy_bidirectional for efficient data transfer
    match io::copy_bidirectional(&mut client_stream, &mut target_stream).await {
        Ok((sent, received)) => {
            println!(
                "Connection closed for {}. Sent {} bytes, received {} bytes.",
                client_addr, sent, received
            );
        }
        Err(e) => {
            eprintln!(
                "Error during data relay for client {}: {}",
                client_addr, e
            );
        }
    }

    Ok(())
}

// Helper function to send a SOCKS5 reply
async fn send_reply(stream: &mut TcpStream, rep_code: u8, bind_addr: SocketAddr) -> io::Result<()> {
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let mut reply = BytesMut::new();
    reply.put_u8(SOCKS_VERSION);
    reply.put_u8(rep_code);
    reply.put_u8(RSV);

    match bind_addr.ip() {
        IpAddr::V4(ipv4) => {
            reply.put_u8(ATYP_IPV4);
            reply.put(&ipv4.octets()[..]);
        }
        IpAddr::V6(ipv6) => {
            reply.put_u8(ATYP_IPV6);
             reply.put(&ipv6.octets()[..]);
        }
    }
    reply.put_u16(bind_addr.port());

    stream.write_all(&reply).await?;
    Ok(())
}
