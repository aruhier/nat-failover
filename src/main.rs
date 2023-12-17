use anyhow::{anyhow, Result};
use clap::Parser;
use futures::{pin_mut, stream::StreamExt};
use iptables::IPTables;
use log::{debug, error, info};
use netdiag::{Bind, Ping, Pinger};
use std::net::IpAddr;
use std::num::ParseIntError;
use std::time::Duration;
use tokio::time::sleep;

mod alerts;

/// NAT failover detects a failure in the routing of an IPv6 block through DHCP-PD by testing
/// pinging an address from the default IP and an IP supposed to be routed.
/// If the first one works but the second one fails, then injects a NAT MASQUERADE rule to temporarily NAT the IPv6
/// traffic until the block is routed again.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None, max_term_width = 100)]
struct Args {
    /// WAN interface.
    #[arg(short, long)]
    iface: String,

    /// IP to bind on.
    #[arg(short, long)]
    from: IpAddr,

    /// IP to ping.
    #[arg(short, long, default_value = "2001:4860:4860::8888")]
    to: IpAddr,

    /// Retries.
    #[arg(short, long, default_value = "5")]
    retries: usize,

    /// Timeout.
    #[arg(long, default_value = "500", value_parser = |arg: &str| -> Result<Duration, ParseIntError> {Ok(Duration::from_millis(arg.parse()?))})]
    timeout: Duration,

    /// Interval in seconds for the testing and apply or clean the failover.
    #[arg(long, default_value = "15", value_parser = |arg: &str| -> Result<Duration, ParseIntError> {Ok(Duration::from_secs(arg.parse()?))})]
    interval: Duration,

    /// Alertmanager URL.
    #[arg(short, long)]
    alertmanager_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    let l = DetectionLoop::new(args).await?;
    l.run().await;

    Ok(())
}

struct DetectionLoop {
    args: Args,
    ping_opts: Ping,
    pinger_default: Pinger,
    pinger_test_from: Pinger,
    iptables_client: IPTables,
}

impl DetectionLoop {
    pub async fn new(args: Args) -> Result<Self> {
        let ping_opts = Ping {
            addr: args.to,
            count: std::cmp::max(args.retries, 1),
            expiry: args.timeout,
        };

        let mut bind_test_from = Bind::default();
        bind_test_from.set(args.from);

        let pinger_default = Pinger::new(&Bind::default()).await?;
        let pinger_test_from = Pinger::new(&bind_test_from).await?;

        let mut iptables_client = iptables::new(true).unwrap();
        iptables_client.set_numeric(true);

        Ok(Self {
            args,
            ping_opts,
            pinger_default,
            pinger_test_from,
            iptables_client,
        })
    }

    pub async fn run(&self) {
        // Sets the NAT switch to force a clean-up of the NAT rule if the first ping succeeds.
        let mut nat_switch = true;
        let mut alert = alerts::Alert::new();

        loop {
            let future_default = ping(&self.args, &self.pinger_default, &self.ping_opts);
            let future_test_from = ping(&self.args, &self.pinger_test_from, &self.ping_opts);

            match future_default.await {
                Ok(_) => {
                    debug!("Ping from default IP succeeded, trying from IP {}...", self.args.from);
                    match future_test_from.await {
                        Err(_) => {
                            let msg = format!(
                                    "Ping from IP {} failed after {} retries. Adding the NAT masquerade rule.",
                                    self.args.from,
                                    self.args.retries,
                                );
                            if !nat_switch {
                                // Only logs in INFO if the NAT switch was off, to not flood the
                                // logs at every loop.
                                info!("{}", msg);
                            } else {
                                debug!("{}", msg);
                            }
                            match self.inject_nat_masquerade() {
                                Err(err) => error!("Error adding the NAT rule: {}", err),
                                Ok(_) => {
                                    nat_switch = true;
                                    alert.trigger(&self.args.alertmanager_url).await;
                                }
                            }
                        }
                        _ => {
                            debug!("Ping from IP {} succeeded.", self.args.from,);
                            if nat_switch {
                                info!("Cleanup the NAT masquerade rule if existing.");
                                match self.cleanup_nat_masquerade() {
                                    Err(err) => error!("Error cleaning the NAT rule: {}", err),
                                    Ok(_) => {
                                        nat_switch = false;
                                        alert.resolve(&self.args.alertmanager_url).await;
                                    }
                                }
                            }
                        }
                    };
                }
                _ => info!(
                    "Ping from the default IP failed after {} retries. Not taking action as the WAN seems to be under problems.",
                    self.args.retries
                ),
            };
            sleep(self.args.interval).await;
        }
    }

    fn inject_nat_masquerade(&self) -> Result<()> {
        match self.iptables_client.exists(
            "nat",
            "POSTROUTING",
            masquerade_rule(self.args.iface.as_str(), self.args.from).as_str(),
        ) {
            Ok(v) => {
                if !v {
                    match self.iptables_client.insert_unique(
                        "nat",
                        "POSTROUTING",
                        masquerade_rule(self.args.iface.as_str(), self.args.from).as_str(),
                        1,
                    ) {
                        Ok(i) => return Ok(i),
                        Err(e) => return Err(anyhow!(format!("{:?}", e))),
                    }
                }

                Ok(())
            }
            Err(e) => Err(anyhow!(format!("{:?}", e))),
        }
    }

    fn cleanup_nat_masquerade(&self) -> Result<()> {
        match self.iptables_client.exists(
            "nat",
            "POSTROUTING",
            masquerade_rule(self.args.iface.as_str(), self.args.from).as_str(),
        ) {
            Ok(v) => {
                if v {
                    match self.iptables_client.delete(
                        "nat",
                        "POSTROUTING",
                        masquerade_rule(self.args.iface.as_str(), self.args.from).as_str(),
                    ) {
                        Ok(i) => return Ok(i),
                        Err(e) => return Err(anyhow!(format!("{:?}", e))),
                    }
                }

                Ok(())
            }
            Err(e) => Err(anyhow!(format!("{:?}", e))),
        }
    }
}

async fn ping(args: &Args, pinger: &Pinger, ping_opts: &Ping) -> Result<()> {
    let stream = pinger.ping(ping_opts).enumerate();
    pin_mut!(stream);

    let mut count = 0;
    let mut errors = 0;
    while let Some((_, item)) = stream.next().await {
        match item? {
            Some(_) => return Ok(()),
            None => {
                errors += 1;
            }
        }

        if errors >= args.retries {
            return Err(anyhow!("number of errors {} exceeded", errors));
        }

        count += 1;
        if count < ping_opts.count {
            sleep(Duration::from_millis(500)).await;
        }
    }

    Ok(())
}

fn masquerade_rule(iface: &str, exclude_ip: IpAddr) -> String {
    format!("-o {} ! -s {} -j MASQUERADE", iface, exclude_ip)
}
