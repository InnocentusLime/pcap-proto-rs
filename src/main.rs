pub mod proto;
use std::{path::PathBuf, net::Ipv4Addr};

use proto::NetworkCfg;
use thiserror::Error;
use clap::{Parser, Subcommand, Args};
use pcap::{Device, Capture, DeviceFlags, IfFlags, Activated};

#[derive(Debug, Error)]
#[error("Invalid MAC address syntax")]
struct ParseMacError;

fn parse_mac(mac_str: &str) -> Result<[u8; 6], ParseMacError> {
    mac_str
        .split(':')
        .filter_map(|x| u8::from_str_radix(x, 16).ok())
        .collect::<Vec<u8>>()
        .try_into()
        .map_err(|_| ParseMacError)
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    List,
    Run {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        output: Output,
        #[command(flatten)]
        net_cfg: NetworkCfgCli,
    },
}

#[derive(Args)]
#[derive(Clone, Copy)]
struct NetworkCfgCli {
    #[arg(long, value_name = "MAC", value_parser = parse_mac)]
    src_mac: Option<[u8; 6]>,
    #[arg(long, value_name = "MAC", value_parser = parse_mac)]
    dst_mac: Option<[u8; 6]>,
    #[arg(long, value_name = "IP")]
    src_ip: Option<Ipv4Addr>,
    #[arg(long, value_name = "IP")]
    dst_ip: Option<Ipv4Addr>,
}

impl NetworkCfgCli {
    #[inline]
    fn is_complete(&self) -> bool {
        self.src_ip.is_some() && self.dst_ip.is_some() && self.src_mac.is_some() &&
            self.dst_mac.is_some()
    }
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Input {
    /// Take input from this device
    #[arg(long, value_name = "DEV")]
    in_dev: Option<String>,
    /// Simulate input from this .pcap file
    #[arg(long, value_name = "FILE")]
    in_file: Option<PathBuf>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Output {
    /// Output to this device
    #[arg(long, value_name = "DEV")]
    out_dev: Option<String>,
    /// Simulate output from this .pcap file
    #[arg(long, value_name = "FILE")]
    out_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let devs = Device::list()?;

    let (input, output, net_cfg) = match args.cmd {
        Command::List => {
            list_devices(devs);
            return Ok(());
        },
        Command::Run { input, output, net_cfg } => (input, output, net_cfg),
    };

    let incap = get_cap(&devs, &input.in_dev, input.in_file)?;
    let outcap = get_cap(&devs, &output.out_dev, output.out_file)?;
    let outdev = input.in_dev.as_ref()
        .and_then(|x| find_device(x, &devs).ok());

    incap.direction(pcap::Direction::In)?;
    outcap.direction(pcap::Direction::Out)?;

    let net_cfg = match (outdev, net_cfg.is_complete()) {
        (_, true) => NetworkCfg {
            client_mac: net_cfg.src_mac.unwrap(),
            client_ip: net_cfg.src_ip.unwrap(),
            server_mac: net_cfg.dst_mac.unwrap(),
            server_ip: net_cfg.dst_ip.unwrap(),
        },
        (Some(dev), false) => guess_net_cfg(net_cfg, dev)?,
        (None, false) => anyhow::bail!("Network configuration incomplete"),
    };

    // 1. Guess/get clients&server mac'n'ip
    // 2. Create the context
    // 3. Run

    Ok(())
}

fn guess_net_cfg(net_cfg: NetworkCfgCli, dev: &Device) -> anyhow::Result<NetworkCfg> {
    let Some(server_mac) = net_cfg.dst_mac else {
        anyhow::bail!("Can't guess server MAC")
    };

    Ok(NetworkCfg {
        server_mac,
        client_mac: todo!(),
        server_ip: todo!(),
        client_ip: todo!(),
    })
}

fn get_cap(
    devs: &Vec<Device>,
    dev: &Option<String>,
    file: Option<PathBuf>,
) -> anyhow::Result<Capture<dyn Activated>> {
    Ok(match (dev, file) {
        (Some(dev), _) => Capture::from_device(
            find_device(&dev, devs)?.clone()
        )?.open()?.into(),
        (_, Some(file)) => Capture::from_file(file)?.into(),
        _ => unreachable!(),
    })
}

fn list_devices(devs: Vec<Device>) {
    for dev in devs {
        print!("{} ", dev.name);
        if let Some(desc) = &dev.desc {
            print!(" ({desc})");
        }
        println!("");
        print_device_flags(&dev.flags);

        for addr in &dev.addresses {
            print!("\tADDR={}", addr.addr);
            if let Some(broad) = &addr.broadcast_addr {
                print!("\tBROADCAST={broad}");
            }
            if let Some(dest) = &addr.dst_addr {
                print!("\tDEST={dest}");
            }
            if let Some(mask) = &addr.netmask {
                print!("\tMASK={mask}");
            }
            println!("");
        }
    }
}

fn print_device_flags(flags: &DeviceFlags) {
    println!("Connection status: {:?}", flags.connection_status);
    let flags = flags.if_flags;
    let is_loopback = flags.intersects(IfFlags::LOOPBACK);
    let is_running = flags.intersects(IfFlags::RUNNING);
    let is_up = flags.intersects(IfFlags::UP);
    let is_wireless = flags.intersects(IfFlags::WIRELESS);
    println!("Flags={:04x}\tLOOPBACK={is_loopback}\tRUNNING={is_running}\tUP={is_up}\tWIRELESS={is_wireless}", flags.bits());
}

fn find_device<'a>(name: &str, devs: &'a[Device]) -> anyhow::Result<&'a Device> {
    devs.iter()
        .find(|x| x.name.eq_ignore_ascii_case(name.trim()))
        .ok_or_else(|| anyhow::anyhow!("Device \"{name}\" not found"))
}