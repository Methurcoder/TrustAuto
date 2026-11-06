//! Installed setuid root and executable only by the `trustauto` group.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(trustauto::broker::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("trustauto-broker only runs on Linux");
    std::process::exit(126);
}
