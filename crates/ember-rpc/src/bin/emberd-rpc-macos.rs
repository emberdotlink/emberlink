#[path = "../bin_support/rpc_main.rs"]
mod rpc_main;

fn main() -> anyhow::Result<()> {
    rpc_main::run()
}
