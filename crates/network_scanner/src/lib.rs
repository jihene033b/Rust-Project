use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

// Nmap top 1000 ports
pub const TOP_1000_PORTS: &[u16] = &[
    1, 2, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53,
    70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135,
    139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
    311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
    512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631,
    636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777,
    783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990,
    992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
    1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057,
    1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
    1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107,
    1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132,
    1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174,
    1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236,
    1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
    1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556,
    1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723,
    1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935,
    1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
    2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045,
    2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
    2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323,
    2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604,
    2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909,
    2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
    3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322,
    3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517,
    3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826,
    3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995,
    3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
    4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001,
    5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102,
    5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432,
    5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800,
    5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904,
    5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988,
    5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101,
    6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646,
    6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000,
    7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496,
    7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001,
    8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
    8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654,
    8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
    9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
    9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898,
    9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009,
    10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626,
    10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001,
    16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
    19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715,
    28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
    45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
    49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
];

pub const TOP_UDP_PORTS: &[u16] = &[
    53, 67, 68, 69, 111, 123, 135, 137, 138, 161, 162, 177, 389, 445, 500, 514, 520, 623, 631,
    1194, 1434, 1900, 4500, 5353, 5355, 10000,
];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum ScanMode {
    #[default]
    TcpConnect,
    Syn,
    Udp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: String,
    pub open_ports: Vec<PortInfo>,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub open_filtered_count: usize,
}

pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub skip_ping: bool,
    pub ports: Vec<u16>,
    pub mode: ScanMode,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 1000,
            timeout_ms: 1000,
            skip_ping: false,
            ports: TOP_1000_PORTS.to_vec(),
            mode: ScanMode::TcpConnect,
        }
    }
}

// converts a port string like `22`, `80,443` or `1-1000` into a list of port numbers
pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let a: u16 = start.trim().parse()?;
            let b: u16 = end.trim().parse()?;
            if a > b {
                return Err(anyhow!("Range invalide : {} > {}", a, b));
            }
            ports.extend(a..=b);
        } else {
            ports.push(part.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

// turns a target string (single IP, CIDR, or range) into a list of IP addresses
pub fn parse_targets(input: &str) -> Result<Vec<IpAddr>> {
    if input.contains('/') {
        parse_cidr(input)
    } else if input.contains('-') {
        parse_range(input)
    } else {
        Ok(vec![input.trim().parse::<IpAddr>()?])
    }
}

// expands a CIDR like `192.168.1.0/24` into all its host IPs
fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid CIDR: {}", cidr))?;

    let base: Ipv4Addr = ip_str.parse()?;
    let prefix: u32 = prefix_str.parse()?;
    ///32 and /31 are handled as special cases.
    if prefix > 32 {
        return Err(anyhow!("Prefix length must be <= 32, got {}", prefix));
    }

    let base_u32 = u32::from(base);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = base_u32 & mask;
    let broadcast = network | !mask;

  
    if prefix == 32 {
        return Ok(vec![IpAddr::V4(base)]);
    }
    if prefix == 31 {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::from(network)),
            IpAddr::V4(Ipv4Addr::from(broadcast)),
        ]);
    }

    Ok((network + 1..broadcast)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect())
}

// expands a range like `192.168.1.1-192.168.1.10` into individual IPs
fn parse_range(range: &str) -> Result<Vec<IpAddr>> {
    let (start_str, end_str) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("Invalid range: {}", range))?;

    let start: Ipv4Addr = start_str.trim().parse()?;
    let end: Ipv4Addr = end_str.trim().parse()?;

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    if start_u32 > end_u32 {
        return Err(anyhow!("Range start is after end: {} > {}", start, end));
    }

    Ok((start_u32..=end_u32)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect())
}

// scans all target hosts one by one, pinging first to check they are alive (unless --no-ping is set)
pub async fn scan(
    targets: Vec<IpAddr>,
    config: ScanConfig,
    tx: mpsc::Sender<(String, PortInfo)>,
) -> Result<Vec<ScanResult>> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let config = Arc::new(config);
    let mut results = Vec::new();

    for ip in targets {
        if !config.skip_ping {
            let alive = ping_host(ip).await;
            if !alive {
                println!(
                    "[-] {} — hôte injoignable (pas de réponse ICMP). Utilisez --no-ping pour forcer.",
                    ip
                );
                continue;
            }
            println!("[*] {} — hôte actif", ip);
        }

        let result = scan_host(ip, &config, &semaphore, &tx).await;
        results.push(result);
    }

    Ok(results)
}

// returns true if the host replies to a ping
pub async fn ping_host(ip: IpAddr) -> bool {
    #[cfg(target_os = "macos")]
    let args = ["-c", "1", "-W", "1000", &ip.to_string()];
    #[cfg(not(target_os = "macos"))]
    let args = ["-c", "1", "-W", "1", &ip.to_string()];

    match timeout(
        Duration::from_secs(2),
        Command::new("ping").args(&args).output(),
    )
    .await
    {
        Ok(Ok(out)) => out.status.success(),
        _ => false,
    }
}

// picks the right scan method (TCP connect, SYN, or UDP) and runs it on one host
async fn scan_host(
    ip: IpAddr,
    config: &ScanConfig,
    semaphore: &Arc<Semaphore>,
    tx: &mpsc::Sender<(String, PortInfo)>,
) -> ScanResult {
    match config.mode {
        ScanMode::TcpConnect => tcp_connect_scan(ip, config, semaphore, tx).await,
        ScanMode::Syn => syn_scan(ip, config, tx).await,
        ScanMode::Udp => udp_scan(ip, config, semaphore, tx).await,
    }
}

// tries to connect to each port: open if it works, closed if refused, filtered if no reply
async fn tcp_connect_scan(
    ip: IpAddr,
    config: &ScanConfig,
    semaphore: &Arc<Semaphore>,
    tx: &mpsc::Sender<(String, PortInfo)>,
) -> ScanResult {
    let mut handles = Vec::with_capacity(config.ports.len());

    for &port in &config.ports {
        let sem = semaphore.clone();
        let tx = tx.clone();
        let ip_str = ip.to_string();
        let timeout_ms = config.timeout_ms;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (state, banner) = probe_port(ip, port, timeout_ms).await;
            let info = PortInfo {
                port,
                state: state.clone(),
                service: service_name(port).to_string(),
                banner,
            };
            if state == PortState::Open {
                let _ = tx.send((ip_str, info.clone())).await;
            }
            info
        }));
    }

    let mut open_ports = Vec::new();
    let mut closed_count = 0;
    let mut filtered_count = 0;

    for handle in handles {
        if let Ok(info) = handle.await {
            match info.state {
                PortState::Open => open_ports.push(info),
                PortState::Closed => closed_count += 1,
                PortState::Filtered => filtered_count += 1,
                PortState::OpenFiltered => filtered_count += 1,
            }
        }
    }
    open_ports.sort_by_key(|p| p.port);

    ScanResult {
        ip: ip.to_string(),
        open_ports,
        closed_count,
        filtered_count,
        open_filtered_count: 0,
    }
}

// sends a UDP packet to each port and checks for a reply
async fn udp_scan(
    ip: IpAddr,
    config: &ScanConfig,
    semaphore: &Arc<Semaphore>,
    tx: &mpsc::Sender<(String, PortInfo)>,
) -> ScanResult {
    let mut handles = Vec::with_capacity(config.ports.len());

    for &port in &config.ports {
        let sem = semaphore.clone();
        let tx = tx.clone();
        let ip_str = ip.to_string();
        let timeout_ms = config.timeout_ms;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (state, banner) = probe_port_udp(ip, port, timeout_ms).await;
            let info = PortInfo {
                port,
                state: state.clone(),
                service: service_name(port).to_string(),
                banner,
            };
            // for UDP we display both open and open|filtered
            if matches!(state, PortState::Open | PortState::OpenFiltered) {
                let _ = tx.send((ip_str, info.clone())).await;
            }
            info
        }));
    }

    let mut open_ports = Vec::new();
    let mut closed_count = 0;
    let mut filtered_count = 0;
    let mut open_filtered_count = 0;

    for handle in handles {
        if let Ok(info) = handle.await {
            match info.state {
                PortState::Open => open_ports.push(info),
                PortState::Closed => closed_count += 1,
                PortState::Filtered => filtered_count += 1,
                PortState::OpenFiltered => {
                    open_filtered_count += 1;
                    open_ports.push(info);
                }
            }
        }
    }
    open_ports.sort_by_key(|p| p.port);

    ScanResult {
        ip: ip.to_string(),
        open_ports,
        closed_count,
        filtered_count,
        open_filtered_count,
    }
}

// Runs the SYN scan in a background thread because pnet uses blocking calls
async fn syn_scan(
    ip: IpAddr,
    config: &ScanConfig,
    tx: &mpsc::Sender<(String, PortInfo)>,
) -> ScanResult {
    let IpAddr::V4(ipv4) = ip else {
        eprintln!("[!] SYN scan: IPv6 non supporté");
        return ScanResult {
            ip: ip.to_string(),
            open_ports: vec![],
            closed_count: 0,
            filtered_count: 0,
            open_filtered_count: 0,
        };
    };

    let ports = config.ports.clone();
    let timeout_ms = config.timeout_ms;

    let states =
        tokio::task::spawn_blocking(move || syn_scan_host_blocking(ipv4, &ports, timeout_ms))
            .await
            .unwrap_or_default();

    let mut open_ports = Vec::new();
    let mut closed_count = 0;
    let mut filtered_count = 0;

    for (port, state) in states {
        let info = PortInfo {
            port,
            state: state.clone(),
            service: service_name(port).to_string(),
            banner: None,
        };
        match state {
            PortState::Open => {
                let _ = tx.send((ip.to_string(), info.clone())).await;
                open_ports.push(info);
            }
            PortState::Closed => closed_count += 1,
            PortState::Filtered | PortState::OpenFiltered => filtered_count += 1,
        }
    }
    open_ports.sort_by_key(|p| p.port);

    ScanResult {
        ip: ip.to_string(),
        open_ports,
        closed_count,
        filtered_count,
        open_filtered_count: 0,
    }
}

// sends raw SYN packets and reads replies to find open ports (needs root to run )
fn syn_scan_host_blocking(
    dest_ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u64,
) -> HashMap<u16, PortState> {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
    use pnet::transport::{
        TransportChannelType::Layer4, TransportProtocol::Ipv4 as PnetIpv4, tcp_packet_iter,
        transport_channel,
    };

    let mut results: HashMap<u16, PortState> =
        ports.iter().map(|&p| (p, PortState::Filtered)).collect();

    let local_ip = match get_local_ipv4() {
        Some(ip) => ip,
        None => {
            eprintln!("[!] SYN scan: impossible de déterminer l'IP locale");
            return results;
        }
    };

    let protocol = Layer4(PnetIpv4(IpNextHeaderProtocols::Tcp));
    let (mut tx_chan, mut rx_chan) = match transport_channel(65536, protocol) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[!] SYN scan nécessite les droits root: {}", e);
            return results;
        }
    };

    let source_port: u16 = 49152;
    let port_set: HashSet<u16> = ports.iter().copied().collect();

    for &port in ports {
        let mut buf = [0u8; 20];
        let mut pkt = MutableTcpPacket::new(&mut buf).unwrap();
        pkt.set_source(source_port);
        pkt.set_destination(port);
        pkt.set_sequence(simple_seq(port));
        pkt.set_acknowledgement(0);
        pkt.set_data_offset(5);
        pkt.set_flags(TcpFlags::SYN);
        pkt.set_window(65535);
        let cksum = pnet::packet::tcp::ipv4_checksum(&pkt.to_immutable(), &local_ip, &dest_ip);
        pkt.set_checksum(cksum);
        let _ = tx_chan.send_to(pkt.to_immutable(), IpAddr::V4(dest_ip));
    }

    let mut iter = tcp_packet_iter(&mut rx_chan);
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms + 2000);
    let mut pending = port_set.len();

    loop {
        if pending == 0 {
            break;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wait = deadline - now;

        match iter.next_with_timeout(wait) {
            Ok(Some((packet, src_addr))) => {
                let src_v4 = match src_addr {
                    IpAddr::V4(v4) => v4,
                    _ => continue,
                };
                if src_v4 != dest_ip {
                    continue;
                }
                if packet.get_destination() != source_port {
                    continue;
                }

                let port = packet.get_source();
                if !port_set.contains(&port) {
                    continue;
                }

                let flags = packet.get_flags();
                let new_state = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                    PortState::Open
                } else if flags & TcpFlags::RST != 0 {
                    PortState::Closed
                } else {
                    continue;
                };

                if results.get(&port) == Some(&PortState::Filtered) {
                    pending = pending.saturating_sub(1);
                }
                results.insert(port, new_state);
            }
            Ok(None) | Err(_) => break,
        }
    }

    results
}

// gives each port a unique sequence number so we can match replies to the right request
fn simple_seq(port: u16) -> u32 {
    0x1337_0000u32 | (port as u32)
}

// finds our local IP address  (need it to build valid SYN packets)
fn get_local_ipv4() -> Option<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        for ip_net in &iface.ips {
            if let IpAddr::V4(v4) = ip_net.ip() {
                return Some(v4);
            }
        }
    }
    None
}

// connects to a TCP port and tries to read the service banner
async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64) -> (PortState, Option<String>) {
    let addr = SocketAddr::new(ip, port);

    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let banner = grab_banner(&mut stream, port, timeout_ms / 2).await;
            (PortState::Open, banner)
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            (PortState::Closed, None)
        }
        _ => (PortState::Filtered, None),
    }
}

// sends a UDP packet and reads the reply to figure out if the port is open or closed, or filtered
async fn probe_port_udp(ip: IpAddr, port: u16, timeout_ms: u64) -> (PortState, Option<String>) {
    let local: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let socket = match tokio::net::UdpSocket::bind(local).await {
        Ok(s) => s,
        Err(_) => return (PortState::Filtered, None),
    };

    let dest = SocketAddr::new(ip, port);
    if socket.connect(dest).await.is_err() {
        return (PortState::Filtered, None);
    }

    let probe = udp_probe(port);
    let _ = timeout(Duration::from_millis(timeout_ms), socket.send(probe)).await;

    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            let raw = String::from_utf8_lossy(&buf[..n]);
            let line = raw.lines().next().map(|l| l.trim().to_string());
            (PortState::Open, line.filter(|s| !s.is_empty()))
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            // ICMP port unreachable → closed
            (PortState::Closed, None)
        }
        _ => (PortState::OpenFiltered, None),
    }
}

// returns the right bytes to send to get a response from a UDP service
fn udp_probe(port: u16) -> &'static [u8] {
    match port {
        
        53 => b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
       
        161 => b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        _ => b"\x00",
    }
}

// reads the first line the server sends after connecting ( sends a HEAD request first for HTTP ports)
async fn grab_banner(stream: &mut TcpStream, port: u16, timeout_ms: u64) -> Option<String> {
    if matches!(port, 80 | 8080 | 8000 | 8008 | 8888) {
        let req = b"HEAD / HTTP/1.0\r\n\r\n";
        let _ = timeout(Duration::from_millis(timeout_ms), stream.write_all(req)).await;
    }

    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = String::from_utf8_lossy(&buf[..n]);
            let line = raw.lines().next()?.trim().to_string();
            if line.is_empty() { None } else { Some(line) }
        }
        _ => None,
    }
}

// returns the service name for a port number (like "ssh" for 22)
fn service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmp-trap",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        515 => "printer",
        520 => "rip",
        587 => "submission",
        623 => "ipmi",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1194 => "openvpn",
        1433 => "mssql",
        1434 => "mssql-m",
        1521 => "oracle",
        1723 => "pptp",
        1900 => "upnp",
        3306 => "mysql",
        3389 => "rdp",
        4500 => "ike-nat",
        5353 => "mdns",
        5355 => "llmnr",
        5432 => "postgresql",
        5900 => "vnc",
        5901 => "vnc-1",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9200 => "elasticsearch",
        10000 => "webmin",
        27017 => "mongodb",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ip() {
        let targets = parse_targets("192.168.1.1").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn parse_cidr_24() {
        let targets = parse_targets("192.168.1.0/24").unwrap();
        assert_eq!(targets.len(), 254);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[253].to_string(), "192.168.1.254");
    }

    #[test]
    fn parse_ip_range() {
        let targets = parse_targets("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(targets.len(), 10);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[9].to_string(), "192.168.1.10");
    }

    #[test]
    fn top_1000_ports_count() {
        assert_eq!(TOP_1000_PORTS.len(), 1000);
    }

    #[test]
    fn parse_cidr_32_returns_single_host() {
        let targets = parse_targets("192.168.1.5/32").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.5");
    }

    #[test]
    fn parse_cidr_31_returns_both_addresses() {
        let targets = parse_targets("192.168.1.4/31").unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].to_string(), "192.168.1.4");
        assert_eq!(targets[1].to_string(), "192.168.1.5");
    }

    #[test]
    fn known_services_are_named() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(80), "http");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(3306), "mysql");
    }
}
