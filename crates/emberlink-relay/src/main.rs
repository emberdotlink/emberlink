use emberlink_relay::{RelayConfig, print_usage, run};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(|a| a.as_str()) == Some("--help")
        || args.first().map(|a| a.as_str()) == Some("-h")
    {
        print_usage();
        return;
    }

    let config = match RelayConfig::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            std::process::exit(1);
        }
    };

    run(config);
}
