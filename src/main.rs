use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr};

use rsdsl_netlinklib::blocking as nl;
use wireguard_control::backends::kernel as wg;

const CONFIG_PATH: &str = "/data/wg.peers";

#[derive(Debug)]
enum ConfigError {
    AddrParse(std::net::AddrParseError),
    BlankLine,
    DuplicateLink(String),
    Eof,
    ExpectedLinkStanza(String),
    IncompleteLinkHead,
    InvalidAllowedIp(String),
    InvalidCidr,
    InvalidKey,
    Io(io::Error),
    NoEndpoint(String),
    NoPrivateKey(String),
    NoPublicKey(String),
    NoPresharedKey(String),
    NoAddresses(String),
    NoAllowedIps(String),
    NoKeepaliveInterval(String),
    NoFwmark(String),
    ParseInt(std::num::ParseIntError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse config: ")?;

        match self {
            Self::AddrParse(e) => write!(f, "parse IP address: {}", e),
            Self::BlankLine => write!(f, "empty line"),
            Self::DuplicateLink(name) => write!(f, "duplicate link {}", name),
            Self::Eof => write!(f, "EOF"),
            Self::ExpectedLinkStanza(kw) => {
                write!(f, "expected \"link\" or \"delete\", got {}", kw)
            }
            Self::IncompleteLinkHead => write!(f, "incomplete link head (want \"link <name>\")"),
            Self::InvalidAllowedIp(allowed_ip) => write!(f, "invalid AllowedIP: {}", allowed_ip),
            Self::InvalidCidr => write!(f, "invalid CIDR (want exactly one /)"),
            Self::InvalidKey => write!(f, "invalid WireGuard key"),
            Self::Io(e) => write!(f, "io: {}", e),
            Self::NoEndpoint(link) => write!(f, "missing endpoint for link {}", link),
            Self::NoPrivateKey(link) => write!(f, "missing private key for link {}", link),
            Self::NoPublicKey(link) => write!(f, "missing public key for link {}", link),
            Self::NoPresharedKey(link) => write!(f, "missing preshared key for link {}", link),
            Self::NoAddresses(link) => write!(f, "missing addresses for link {}", link),
            Self::NoAllowedIps(link) => write!(f, "missing AllowedIPs for link {}", link),
            Self::NoKeepaliveInterval(link) => {
                write!(f, "missing keepalive interval for link {}", link)
            }
            Self::NoFwmark(link) => write!(f, "missing fwmark for link {}", link),
            Self::ParseInt(e) => write!(f, "parse int: {}", e),
        }
    }
}

impl From<std::net::AddrParseError> for ConfigError {
    fn from(e: std::net::AddrParseError) -> ConfigError {
        ConfigError::AddrParse(e)
    }
}

impl From<wireguard_control::InvalidKey> for ConfigError {
    fn from(_: wireguard_control::InvalidKey) -> ConfigError {
        ConfigError::InvalidKey
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> ConfigError {
        ConfigError::Io(e)
    }
}

impl From<std::num::ParseIntError> for ConfigError {
    fn from(e: std::num::ParseIntError) -> ConfigError {
        ConfigError::ParseInt(e)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug)]
enum SetupError {
    InvalidInterfaceName(String, wireguard_control::InvalidInterfaceName),
    Io(io::Error),
    Netlinklib(rsdsl_netlinklib::Error),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "set up link: ")?;

        match self {
            Self::InvalidInterfaceName(name, e) => {
                write!(f, "invalid interface name {}: {}", name, e)
            }
            Self::Io(e) => write!(f, "io: {}", e),
            Self::Netlinklib(e) => write!(f, "rsdsl_netlinklib: {}", e),
        }
    }
}

impl From<io::Error> for SetupError {
    fn from(e: io::Error) -> SetupError {
        SetupError::Io(e)
    }
}

impl From<rsdsl_netlinklib::Error> for SetupError {
    fn from(e: rsdsl_netlinklib::Error) -> SetupError {
        SetupError::Netlinklib(e)
    }
}

impl std::error::Error for SetupError {}

#[derive(Debug)]
enum Error {
    Config(ConfigError),
    Setup(SetupError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::Setup(e) => e.fmt(f),
        }
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Error {
        Error::Config(e)
    }
}

impl From<SetupError> for Error {
    fn from(e: SetupError) -> Error {
        Error::Setup(e)
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct IpConfig {
    addresses: Vec<(IpAddr, u8)>,
    allowed_ips: Vec<wireguard_control::AllowedIp>,
}

#[derive(Debug)]
struct Link {
    endpoint: SocketAddr,
    private_key: wireguard_control::Key,
    public_key: wireguard_control::Key,
    preshared_key: wireguard_control::Key,
    ip_config: IpConfig,
    keepalive_seconds: u16,
    fwmark: u32,
}

#[derive(Debug)]
enum LinkStanza {
    Link(Link),
    Delete,
}

#[derive(Debug)]
struct LinkConfig {
    name: String,
    link: LinkStanza,
}

impl LinkConfig {
    fn parse<R: io::BufRead>(r: &mut R) -> Result<Self, ConfigError> {
        let mut head = String::new();
        let mut n = r.read_line(&mut head)?;
        if n == 0 {
            return Err(ConfigError::Eof);
        }
        if head == "\n" {
            return Err(ConfigError::BlankLine);
        }
        head.pop();

        let head: Vec<&str> = head.split(' ').collect();
        if head.len() < 2 {
            return Err(ConfigError::IncompleteLinkHead);
        }

        let name = head[1].to_string();

        let link_keyword = head[0];
        if link_keyword == "delete" {
            return Ok(Self {
                name,
                link: LinkStanza::Delete,
            });
        } else if link_keyword != "link" {
            return Err(ConfigError::ExpectedLinkStanza(link_keyword.to_string()));
        }

        let mut endpoint = String::new();
        n = r.read_line(&mut endpoint)?;
        if n == 0 {
            return Err(ConfigError::NoEndpoint(name));
        }
        endpoint.pop();
        let endpoint: SocketAddr = endpoint.parse()?;

        let mut private_key = String::new();
        n = r.read_line(&mut private_key)?;
        if n == 0 {
            return Err(ConfigError::NoPrivateKey(name));
        }
        private_key.pop();
        let private_key = wireguard_control::Key::from_base64(&private_key)?;

        let mut public_key = String::new();
        n = r.read_line(&mut public_key)?;
        if n == 0 {
            return Err(ConfigError::NoPublicKey(name));
        }
        public_key.pop();
        let public_key = wireguard_control::Key::from_base64(&public_key)?;

        let mut preshared_key = String::new();
        n = r.read_line(&mut preshared_key)?;
        if n == 0 {
            return Err(ConfigError::NoPresharedKey(name));
        }
        preshared_key.pop();
        let preshared_key = wireguard_control::Key::from_base64(&preshared_key)?;

        let mut addresses = String::new();
        n = r.read_line(&mut addresses)?;
        if n == 0 {
            return Err(ConfigError::NoAddresses(name));
        }
        addresses.pop();

        let address_strs = addresses.split(' ');
        let mut addresses = Vec::new();

        for address_str in address_strs {
            let parts: Vec<&str> = address_str.split('/').collect();
            if parts.len() != 2 {
                return Err(ConfigError::InvalidCidr);
            }

            let address: IpAddr = parts[0].parse()?;
            let prefix_length: u8 = parts[1].parse()?;

            addresses.push((address, prefix_length));
        }

        let mut allowed_ips = String::new();
        n = r.read_line(&mut allowed_ips)?;
        if n == 0 {
            return Err(ConfigError::NoAllowedIps(name));
        }
        allowed_ips.pop();

        let allowed_ip_strs = allowed_ips.split(' ');
        let mut allowed_ips = Vec::new();

        for allowed_ip_str in allowed_ip_strs {
            let allowed_ip: wireguard_control::AllowedIp = allowed_ip_str
                .parse()
                .map_err(|_| ConfigError::InvalidAllowedIp(allowed_ip_str.to_string()))?;
            allowed_ips.push(allowed_ip);
        }

        let mut keepalive_seconds = String::new();
        n = r.read_line(&mut keepalive_seconds)?;
        if n == 0 {
            return Err(ConfigError::NoKeepaliveInterval(name));
        }
        keepalive_seconds.pop();

        let keepalive_seconds: u16 = keepalive_seconds.parse()?;

        let mut fwmark = String::new();
        n = r.read_line(&mut fwmark)?;
        if n == 0 {
            return Err(ConfigError::NoFwmark(name));
        }
        fwmark.pop();

        let fwmark: u32 = fwmark.parse()?;

        Ok(Self {
            name,
            link: LinkStanza::Link(Link {
                endpoint,
                private_key,
                public_key,
                preshared_key,
                ip_config: IpConfig {
                    addresses,
                    allowed_ips,
                },
                keepalive_seconds,
                fwmark,
            }),
        })
    }
}

#[derive(Debug)]
struct Config {
    links: HashMap<String, LinkStanza>,
}

impl Config {
    fn parse<R: io::BufRead>(r: &mut R) -> Result<Self, ConfigError> {
        let mut links = HashMap::new();
        loop {
            let link_config = LinkConfig::parse(r);
            match link_config {
                Err(ConfigError::BlankLine) => continue,
                Err(ConfigError::Eof) => break,
                _ => {}
            }
            let link_config = link_config?;

            if links
                .insert(link_config.name.clone(), link_config.link)
                .is_some()
            {
                return Err(ConfigError::DuplicateLink(link_config.name));
            }
        }

        Ok(Self { links })
    }
}

fn main() {
    println!("[info] init");
    match run() {
        Ok(_) => loop {
            std::thread::park()
        },
        Err(e) => {
            eprintln!("[warn] {}", e);
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), Error> {
    let f = match File::open(CONFIG_PATH) {
        Ok(f) => f,
        Err(e) => return Err(ConfigError::Io(e).into()),
    };
    let mut br = io::BufReader::new(f);
    let config = Config::parse(&mut br)?;

    for (name, link_stanza) in config.links {
        match link_stanza {
            LinkStanza::Link(link) => {
                delete(name.clone())?;
                configure(name, link)?;
            }
            LinkStanza::Delete => delete(name)?,
        };
    }

    Ok(())
}

fn configure(name: String, link: Link) -> Result<(), SetupError> {
    let addresses_pretty = link
        .ip_config
        .addresses
        .iter()
        .map(|(addr, cidr)| format!("{}/{}", addr, cidr))
        .reduce(|acc, net| acc + " " + &net)
        .unwrap_or_default();

    let allowed_ips_pretty = link
        .ip_config
        .allowed_ips
        .iter()
        .map(|net| format!("{}/{}", net.address, net.cidr))
        .reduce(|acc, net| acc + " " + &net)
        .unwrap_or_default();

    println!("[info] configure {}", name);
    println!("[info]   endpoint: {}", link.endpoint);
    println!("[info]   private key: (hidden)");
    println!("[info]   public key: {}", link.public_key.to_base64());
    println!("[info]   preshared key: (hidden)");
    println!("[info]   addresses: {}", addresses_pretty);
    println!("[info]   AllowedIPs: {}", allowed_ips_pretty);
    if link.keepalive_seconds == 0 {
        println!("[info]   keepalive: disabled");
    } else {
        println!("[info]   keepalive: {}", link.keepalive_seconds);
    }
    if link.fwmark == 0 {
        println!("[info]   fwmark: disabled");
    } else {
        println!("[info]   fwmark: {}", link.fwmark);
    }

    let iface: wireguard_control::InterfaceName = match name.parse() {
        Ok(name) => name,
        Err(e) => return Err(SetupError::InvalidInterfaceName(name, e)),
    };

    let mut peer = wireguard_control::PeerConfigBuilder::new(&link.public_key)
        .set_endpoint(link.endpoint)
        .set_preshared_key(link.preshared_key)
        .replace_allowed_ips()
        .add_allowed_ips(&link.ip_config.allowed_ips);

    if link.keepalive_seconds != 0 {
        peer = peer.set_persistent_keepalive_interval(link.keepalive_seconds);
    }

    let mut dev = wireguard_control::DeviceUpdate::new()
        .set_keypair(wireguard_control::KeyPair::from_private(link.private_key))
        .replace_peers()
        .randomize_listen_port()
        .add_peer(peer);
    if link.fwmark != 0 {
        dev = dev.set_fwmark(link.fwmark);
    }
    dev.apply(&iface, wireguard_control::Backend::Kernel)?;

    configure_netlink(name, link.ip_config)
}

fn configure_netlink(name: String, ip_config: IpConfig) -> Result<(), SetupError> {
    let conn = nl::Connection::new()?;

    conn.link_set(name.clone(), true)?;

    for (addr, prefix_length) in ip_config.addresses {
        conn.address_add(name.clone(), addr, prefix_length)?;
    }

    Ok(())
}

fn delete(name: String) -> Result<(), SetupError> {
    let iface: wireguard_control::InterfaceName = match name.parse() {
        Ok(name) => name,
        Err(e) => return Err(SetupError::InvalidInterfaceName(name, e)),
    };

    match wg::delete_interface(&iface) {
        Ok(_) => println!("[info] delete {}", name),
        Err(e) => println!("[warn] delete {}: {}", name, e),
    };

    Ok(())
}
