use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
// TODO: clean all this up
pub struct Args {
    #[arg(short, long)]
    pub listen: bool,
    #[arg(short, long)]
    pub debug: bool,
    // TODO: actually make this hostname, currently just parsing as ip addr
    #[arg(help = "Hostname to either connect to or listen on (i.e. localhost)")]
    pub hostname: String,
    #[arg(
        help = "Port to utilize. If in server mode, this is the port to listen on. If in client mode, this is the port to connect to."
    )]
    pub port: u16,
}
