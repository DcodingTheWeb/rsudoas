const AUTH_MODE: &'static str = "pam";
const SAFE_PATH: &'static str = "/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin";

fn main() {
	let mut var;
	
	println!("cargo::rerun-if-env-changed=SAFE_PATH");
	var = option_env!("SAFE_PATH").unwrap_or(SAFE_PATH);
	println!("cargo::rustc-env=SAFE_PATH={var}");
	
	println!("cargo::rerun-if-env-changed=DEFAULT_CONF_PATH");
	var = option_env!("DEFAULT_CONF_PATH").unwrap_or("/dev/null");
	println!("cargo::rustc-env=DEFAULT_CONF_PATH={var}");
	
	println!("cargo::rerun-if-env-changed=AUTH_MODE");
	var = option_env!("AUTH_MODE").unwrap_or(AUTH_MODE);
	match var {
		"none" => (), // No authentication (only `nopass` rules work)
		"pam" => (), // PAM
		"plain" => (), // Password challenge (Not recommended, prone to brute force)
		_ => panic!("AUTH_MODE is set to an invalid value!"),
	}
	println!("cargo::rustc-cfg=auth=\"{var}\"");
	println!(r#"cargo::rustc-check-cfg=cfg(auth, values("none", "pam", "plain"))"#);
}
