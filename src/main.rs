/*
rsudoas - Privilege escalation utility
Copyright (C) 2023  TheDcoder <TheDcoder@protonmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
	env,
	ffi::CString,
	ptr,
};

use libc;
use pwd_grp;
use syslog_c::syslog;
use nix;

#[allow(unused_imports)]
use rsudoas::{
	auth::*,
	command::*,
	config::*,
	*,
};

const SAFE_PATH: &'static str = env!("SAFE_PATH");
const DEFAULT_CONF: &'static str = include_str!(env!("DEFAULT_CONF_PATH"));

fn main() {
	let command = Command::new();
	match command {
		Command::Execute (opts) => execute(opts),
		Command::Deauth => (),
	};
}

fn execute(opts: Execute) {
	let only_check;
	let config_file;
	match opts.config_file {
		None => {
			only_check = false;
			config_file = String::from("/etc/doas.conf");
		},
		Some(file) => {
			only_check = true;
			config_file = file;
		},
	}
	let config = std::fs::read_to_string(config_file).unwrap_or_else(|e| {
		print_error(&format!("Failed to read config: {e}"));
		if only_check || DEFAULT_CONF.is_empty() {
			std::process::exit(1);
		}
		
		print_error("Falling back to the following default safe conf:");
		eprint!("{DEFAULT_CONF}");
		
		DEFAULT_CONF.into()
	});
	let rules = match Rules::try_from(&*config) {
		Ok(x) => x,
		Err(error) => {
			print_error(&format!("Error parsing config: {error}"));
			if !only_check && !DEFAULT_CONF.is_empty() {
				print_error("Falling back to the following default safe conf:");
				eprint!("{DEFAULT_CONF}");
				
				match Rules::try_from(DEFAULT_CONF) {
					Ok(x) => x,
					Err(error) => print_error_and_exit(&format!("Error parsing fallback config: {error}"), 1),
				}
			} else {
				std::process::exit(1);
			}
		},
	};
	
	let passwd = pwd_grp::getpwuid(pwd_grp::getuid()).unwrap().unwrap();
	let user = &passwd.name;
	let groups = Vec::from_iter(pwd_grp::getgroups().unwrap().iter().map(|x| {
		pwd_grp::getgrgid(*x).unwrap().unwrap().name
	}));
	let passwd_target = match pwd_grp::getpwnam(&opts.user) {
		Err(_) => print_error_and_exit("Failed to retrieve target user", 1),
		Ok(None) => print_error_and_exit("Target user does not exist", 1),
		Ok(Some(x)) => x,
	};
	let cmd = match opts.cmd {
		Some(x) => x,
		None => passwd_target.shell.clone(),
	};
	let matched = rules.r#match(user, &groups, &*cmd, &opts.args, &opts.user);
	if only_check {
		match matched {
			None => println!("deny"),
			Some(rule_opts) => {
				println!("permit{}", if rule_opts.nopass {" nopass"} else {""});
			},
		}
		return;
	}
	
	let rule_opts = match matched {
		None => {
			let cmdline = get_cmdline(&cmd, &opts.args);
			let msg = format!("command not permitted for {}: {}", &user, &cmdline);
			syslog(libc::LOG_AUTHPRIV | libc::LOG_NOTICE, &msg);
			print_error_and_exit("Not permitted", 1);
		},
		Some(match_opts) => match_opts,
	};
	
	let run = |cleanup: Option<Box<dyn FnOnce()>>| -> Result<(), String> {
		use nix::{
			errno::Errno,
			spawn,
			sys::wait::{waitpid, WaitStatus},
			unistd,
		};
		let mut exit_code = 1;
		let mut exit_msg = None;
		
		if !rule_opts.nolog {
			let cmdline = get_cmdline(&cmd, &opts.args);
			let cwd = env::current_dir();
			let cwd = match &cwd {
				Ok(dir) => dir.to_str().unwrap_or("(invalid utf8)"),
				Err(_) => "(failed)",
			};
			let msg = format!("{} ran command {} as {} from {}", &user, &cmdline, &opts.user, &cwd);
			syslog(libc::LOG_AUTHPRIV | libc::LOG_INFO, &msg);
		}
		
		let cmd_cstr;
		unsafe {
			env::set_var("PATH", SAFE_PATH);
			cmd_cstr = CString::new(cmd.clone()).unwrap_unchecked();
		}
		let arg_cstrs: Vec<_> = opts.args.iter().map(|arg| CString::new(arg.as_bytes()).unwrap()).collect();
		
		let mut env_cstrs = vec![
			env_cstr("DOAS_USER", &passwd.name),
			env_cstr("HOME", &passwd_target.dir),
			env_cstr("LOGNAME", &passwd_target.name),
			env_cstr("PATH", SAFE_PATH),
			env_cstr("SHELL", &passwd_target.shell),
			env_cstr("USER", &passwd_target.name),
		];
		for var in ["DISPLAY", "TERM"] {
			if let Ok(value) = env::var(var) {
				let var_cstr = env_cstr(var, &value);
				env_cstrs.push(var_cstr);
			}
		}
		match rule_opts.setenv {
			Some(mut env) => {
				if rule_opts.keepenv {
					for (key, value) in env::vars() {
						if !env.contains_key(&key) {
							env.insert(key, value);
						}
					}
				}
				env_cstrs.extend(env.iter().map(|(&ref key, &ref value)| env_cstr(key, value)));
			},
			None => (),
		}
		let mut env_ptrs: Vec<_> = env_cstrs.iter().map(|arg| arg.as_ptr()).collect();
		env_ptrs.push(ptr::null());
		
		unistd::setresgid(passwd_target.gid.into(), passwd_target.gid.into(), passwd_target.gid.into())
			.map_err(|e| format!("setresgid: {e}"))?;
		let target_name = CString::new(passwd_target.name.clone())
			.map_err(|_| "Invalid username".to_string())?;
		unistd::initgroups(&target_name, passwd_target.gid.into())
			.map_err(|e| format!("initgroups: {e}"))?;
		unistd::setresuid(passwd_target.uid.into(), passwd_target.uid.into(), passwd_target.uid.into())
			.map_err(|e| format!("setresuid: {e}"))?;
			env::set_var("PATH", SAFE_PATH);
		let child_pid = spawn::posix_spawnp(
			cmd_cstr.as_c_str(),
			&spawn::PosixSpawnFileActions::init()
				.map_err(|e| format!("posix_spawn_file_actions_t: {e}"))?,
			&spawn::PosixSpawnAttr::init()
				.map_err(|e| format!("posix_spawnattr_t: {e}"))?,
			&[&cmd_cstr] // Required because we are building a raw `argv`
				.into_iter()
				.chain(arg_cstrs.iter())
				.map(|x| x.as_c_str())
				.collect::<Vec<_>>(),
			&env_cstrs
				.iter()
				.map(|x| x.as_c_str())
				.collect::<Vec<_>>(),
		).map_err(|e| format!("posix_spawnp: {e}"))?;
			
		loop {
			// Wait for child to exit
			match waitpid(Some(child_pid), None) {
				Ok(status) => match status {
					WaitStatus::Exited(_, code) => {
						// Pass the exit code
						exit_code = code;
						break;
					},
					WaitStatus::Signaled(_, signal, _) => {
						exit_msg = Some(format!("{}: killed by signal {}", &cmd, signal.as_str()));
						break;
					},
					_ => (), // Loop until exit
				},
				Err(errno) => {
					if errno == Errno::ENOENT {
						exit_msg = Some(format!("{}: command not found", &cmd));
					} else {
						exit_msg = Some(format!("waitpid: {}", errno.desc()));
					}
					break;
				},
			}
		}
		
		if let Some(cleanup) = cleanup {
			cleanup();
		}
		
		if let Some(msg) = exit_msg {
			print_error_and_exit(&msg, exit_code);
		}
		
		Ok(())
	};
	
	let run_result;
	
	#[cfg(auth = "none")]
	{
		if !rule_opts.nopass {
			eprintln!("This command requires authentication but this version of rsudoas was built without any authentication methods!");
			return;
		}
		
		run_result = run(None);
	}
	
	#[cfg(auth = "pam")]
	{
		use pam_client;
		
		let mut pam_context;
		let mut pam_session = None;
		
		if !rule_opts.nopass {
			match authenticate(&passwd, &passwd_target) {
				Ok(transaction) => {
					pam_context = transaction.context.unwrap();
					
					// Start a PAM session
					pam_session = Some(pam_context.open_session(pam_client::Flag::NONE).expect("Failed to start PAM session"));
				},
				Err(_) => {
					// TODO: Syslog
					eprintln!("Authentication failed");
					return;
				},
			}
		}
		
		run_result = run(Some(Box::new(|| {
			// Close the PAM session
			if let Some(session) = pam_session {
				let _ = session.close(pam_client::Flag::NONE);
			}
		})));
		
		fn authenticate<'a>(source: &'a pwd_grp::Passwd, target: &'a pwd_grp::Passwd) -> Result<Transaction<'a>, ()> {
			let mut transaction = Transaction::new();
			
			match transaction.begin(&source, &target) {
				Ok(_) => Ok(transaction),
				Err(_) => Err(()),
			}
		}
	}
	
	#[cfg(auth = "plain")]
	{
		if !rule_opts.nopass {
			if !challenge_user(&passwd) {
				eprintln!("Authentication failed");
				return;
			}
		}
		
		run_result = run(None);
	}
	
	if let Err(msg) = run_result {
		print_error_and_exit(&format!("Error while trying to run: {msg}"), 1);
	}
	
	fn env_cstr(key: &str, value: &str) -> CString {
		let mut env_str = String::from(key);
		env_str.push('=');
		env_str.push_str(value);
		
		unsafe {
			CString::new(env_str).unwrap_unchecked()
		}
	}
	
	fn get_cmdline(cmd: &String, args: &Vec<String>) -> String {
		let mut cmdline = cmd.clone();
		if args.len() > 0 {
			cmdline.push(' ');
			let args = args.join(" ");
			cmdline.push_str(&args);
		}
		cmdline
	}
}
