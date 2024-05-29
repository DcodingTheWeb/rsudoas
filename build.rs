const SAFE_PATH: &'static str = "/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin";

fn main() {
	let mut var;
	
	println!("cargo::rerun-if-env-changed=SAFE_PATH");
	var = option_env!("SAFE_PATH").unwrap_or(SAFE_PATH);
	println!("cargo::rustc-env=SAFE_PATH={var}");
}
