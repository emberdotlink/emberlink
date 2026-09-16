mod host_adapter_common;

use ember_authority::host_client::AdapterRole;

fn main() {
    host_adapter_common::run("ember-host-planner", AdapterRole::Planner);
}
