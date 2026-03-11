mod config;
mod credentials;
mod openvpn;

use colored::Colorize;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help(&args[0]);
        return;
    }

    match args[1].as_str() {
        "save-auth" => {
            if args.len() < 3 {
                eprintln!("{} {} save-auth <config_name>", "Usage:".bold(), args[0]);
                process::exit(1);
            }
            let config_name = &args[2];
            if let Err(e) = credentials::save_credentials(config_name) {
                eprintln!("{} {}", "✗".red().bold(), e);
                process::exit(1);
            }
        }
        "list-configs" => {
            if let Err(e) = credentials::list_configs() {
                eprintln!("{} {}", "✗".red().bold(), e);
                process::exit(1);
            }
        }
        "delete-auth" => {
            if args.len() < 3 {
                eprintln!("{} {} delete-auth <config_name>", "Usage:".bold(), args[0]);
                process::exit(1);
            }
            let config_name = &args[2];
            if let Err(e) = credentials::delete_credentials(config_name) {
                eprintln!("{} {}", "✗".red().bold(), e);
                process::exit(1);
            }
        }
        "connect" => {
            if args.len() < 3 {
                eprintln!("{} {} connect <config_name> [-v] [extra openvpn args...]", "Usage:".bold(), args[0]);
                process::exit(1);
            }
            let config_name = &args[2];

            // Parse flags: -v/--verbose
            let mut extra_args = Vec::new();
            let mut verbose = false;
            for arg in &args[3..] {
                match arg.as_str() {
                    "-v" | "--verbose" => verbose = true,
                    _ => extra_args.push(arg.clone()),
                }
            }

            if let Err(e) = openvpn::connect(config_name, &extra_args, verbose) {
                eprintln!("{} {}", "✗".red().bold(), e);
                process::exit(1);
            }
        }
        "--help" | "-h" | "--help-wrapper" => {
            print_help(&args[0]);
        }
        _ => {
            // Forward everything to OpenVPN transparently
            println!("{}", "  Forwarding commands to OpenVPN natively...".dimmed());
            if let Err(e) = openvpn::forward(&args[1..]) {
                eprintln!("{} {}", "✗".red().bold(), e);
                process::exit(1);
            }
        }
    }
}

fn print_help(program: &str) {
    println!("{}", format!("🔒 OpenVPN Wrapper v{}", env!("CARGO_PKG_VERSION")).bold().cyan());
    println!();
    println!("{}", "USAGE:".bold().yellow());
    println!("  {} <command> [args...]", program);
    println!();
    println!("{}", "COMMANDS:".bold().yellow());
    println!("  {}   Save credentials for a VPN config", "save-auth <config_name>".green());
    println!("  {}  Delete saved credentials", "delete-auth <config_name>".green());
    println!("  {}               List saved VPN configurations", "list-configs".green());
    println!("  {} Connect using saved credentials", "connect <config_name> [-v]".green());
    println!("  {}          Forward directly to openvpn", "<any openvpn args...>".dimmed());
    println!();
    println!("{}", "FLAGS:".bold().yellow());
    println!("  {}              Show full OpenVPN output", "-v, --verbose".green());
    println!();
    println!("{}", "EXAMPLES:".bold().yellow());
    println!("  {} save-auth work-vpn", program);
    println!("  {} connect work-vpn", program);
    println!("  {} connect work-vpn -v", program);
    println!("  {} --version {}", program, "(forwarded to openvpn)".dimmed());
}
