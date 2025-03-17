use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::net::IpAddr;

const CONFIG_PATH: &str = "/data/wg.peers";

#[derive(Debug)]
enum ConfigError {
    AddrParse(std::net::AddrParseError),
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
    ParseInt(std::num::ParseIntError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse config: ")?;

        match self {
            Self::AddrParse(e) => write!(f, "parse IP address: {}", e),
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
    fn from(e: wireguard_control::InvalidKey) -> ConfigError {
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
enum Error {
    Config(ConfigError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
        }
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Error {
        Error::Config(e)
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct Link {
    endpoint: SocketAddr,
    private_key: wireguard_control::Key,
    public_key: wireguard_control::Key,
    preshared_key: wireguard_control::Key,
    addresses: Vec<(IpAddr, u8)>,
    allowed_ips: Vec<wireguard_control::AllowedIp>,
    keepalive_seconds: u16,
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
        let endpoint: SocketAddr = endpoint.parse()?;

        let mut private_key = String::new();
        n = r.read_line(&mut private_key)?;
        if n == 0 {
            return Err(ConfigError::NoPrivateKey(name));
        }
        let private_key = wireguard_control::Key::from_base64(&private_key)?;

        let mut public_key = String::new();
        n = r.read_line(&mut public_key)?;
        if n == 0 {
            return Err(ConfigError::NoPublicKey(name));
        }
        let public_key = wireguard_control::Key::from_base64(&public_key)?;

        let mut preshared_key = String::new();
        n = r.read_line(&mut preshared_key)?;
        if n == 0 {
            return Err(ConfigError::NoPresharedKey(name));
        }
        let preshared_key = wireguard_control::Key::from_base64(&preshared_key)?;

        let mut addresses = String::new();
        n = r.read_line(&mut addresses)?;
        if n == 0 {
            return Err(ConfigError::NoAddresses(name));
        }

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

        let keepalive_seconds: u16 = keepalive_seconds.parse()?;

        Ok(Self {
            name,
            link: LinkStanza::Link(Link {
                endpoint,
                private_key,
                public_key,
                preshared_key,
                addresses,
                allowed_ips,
                keepalive_seconds,
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
            let eof = Self::skip_blank_lines(r)?;
            if eof {
                break;
            }

            let link_config = LinkConfig::parse(r);
            if let Err(ConfigError::Eof) = link_config {
                break;
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

    fn skip_blank_lines<R: io::BufRead>(r: &mut R) -> Result<bool, ConfigError> {
        let mut s = String::new();
        while r.read_line(&mut s)? > 0 {
            if s != "\n" {
                return Ok(false);
            }

            s.clear();
        }

        Ok(true)
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
}
