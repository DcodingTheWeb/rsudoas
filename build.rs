const SAFE_PATH: &'static str = "/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin";

fn main() {
	match option_env!("SAFE_PATH") {
		None => println!("cargo:rustc-env=SAFE_PATH={SAFE_PATH}"),
		Some(_) => (),
	}
}
