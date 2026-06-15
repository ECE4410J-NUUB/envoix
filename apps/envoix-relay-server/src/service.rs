//! Service lifecycle: thin wrappers over systemctl for the installed unit.
//!
//! systemd owns supervision (start/stop, boot-persistence, restart). These
//! just save the operator from remembering the unit name.

use std::process::Command;

const UNIT: &str = "envoix-relay";

/// Enable on boot and start now.
pub fn up() {
    systemctl(&["enable", "--now", UNIT]);
}

/// Stop the running service.
pub fn down() {
    systemctl(&["stop", UNIT]);
}

fn systemctl(args: &[&str]) {
    match Command::new("systemctl").args(args).status() {
        Ok(status) if status.success() => println!("systemctl {} ok", args.join(" ")),
        Ok(status) => {
            eprintln!("systemctl {} failed ({status})", args.join(" "));
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("could not run systemctl: {e}");
            eprintln!("is systemd present, and do you have sufficient privileges (try sudo)?");
            std::process::exit(1);
        }
    }
}
