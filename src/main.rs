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

#[allow(unused_imports)]
use rsudoas::{
	auth::*,
	command::*,
	config::*,
	*,
};

const SAFE_PATH: &'static str = env!("SAFE_PATH");

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
	let config = std::fs::read_to_string(config_file).expect("Failed to read config");
	let rules = match Rules::try_from(&*config) {
		Ok(x) => x,
		Err(_) => print_error_and_exit("Error parsing config", 1),
	};
	
	let passwd = pwd_grp::getpwuid(pwd_grp::getuid()).unwrap().unwrap();
	let user = &passwd.name;
	let groups = Vec::from_iter(pwd_grp::getgroups().unwrap().iter().map(|x| {
		pwd_grp::getgrgid(*x).unwrap().unwrap().name
	}));
	let passwd_target = match pwd_grp::getpwnam(&opts.user) {
		Err(_) => print_error_and_exit("Failed to retrieve target user", 1),
		Ok(o) => match o {
			None => print_error_and_exit("Target user does not exist", 1),
			Some(x) => x,
		},
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
	if !rule_opts.nopass {
		if !challenge_user(&passwd) {
			eprintln!("Authentication failed");
			return;
		}
	}
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
		libc::setenv(
			CString::new("PATH").unwrap_unchecked().as_ptr(),
			CString::new(SAFE_PATH).unwrap_unchecked().as_ptr(),
			1,
		);
		cmd_cstr = CString::new(cmd.clone()).unwrap_unchecked();
	}
	let arg_cstrs: Vec<_> = opts.args.iter().map(|arg| CString::new(arg.as_bytes()).unwrap()).collect();
	let mut arg_ptrs = vec![cmd_cstr.as_ptr()];
	arg_ptrs.extend(arg_cstrs.iter().map(|arg| arg.as_ptr()));
	arg_ptrs.push(ptr::null());
	
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
	
	unsafe {
		if libc::setresgid(passwd_target.gid, passwd_target.gid, passwd_target.gid) != 0 {
			print_error_and_exit("setresgid", 1);
		}
		let target_name = CString::new(passwd_target.name.clone()).unwrap();
		if libc::initgroups(target_name.as_ptr(), passwd_target.gid) != 0 {
			print_error_and_exit("initgroups", 1);
		}
		if libc::setresuid(passwd_target.uid, passwd_target.uid, passwd_target.uid) != 0 {
			print_error_and_exit("setresuid", 1);
		}
		env::set_var("PATH", SAFE_PATH);
		libc::execvpe(
			cmd_cstr.as_ptr(),
			arg_ptrs.as_ptr(),
			env_ptrs.as_ptr(),
		);
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
