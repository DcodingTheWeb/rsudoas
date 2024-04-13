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

pub mod auth {
    use std::{ffi::{CStr, CString}, io::Write};
	
	use nix;
	use pwd_grp;
	use rpassword::read_password;
	use shadow::Shadow;

	#[link(name = "crypt")]
	extern {
		fn crypt(phrase: *const libc::c_char, setting: *const libc::c_char) -> *const libc::c_char;
	}
	
	pub fn challenge_user(passwd: &pwd_grp::Passwd) -> bool {
		let hostname = nix::unistd::gethostname().expect("Failed to get hostname");
		let hostname = hostname.into_string().expect("Hostname is not valid UTF-8");
		print!("rsudoas ({}@{}) password: ", &passwd.name, &hostname);
		std::io::stdout().flush().unwrap();
		let response = match read_password() {
			Ok(x) => x,
			Err(_) => return false,
		};
		let mut hash = &passwd.passwd;
		let shadow;
		if hash == "x" {
			shadow = match Shadow::from_name(&passwd.name) {
				Some(x) => x,
				None => return false,
			};
			hash = &shadow.password;
		}
		verify_hash(hash, &response)
	}
	
	pub fn verify_hash(hash: &str, response: &str) -> bool {
		unsafe {
			let hash = CString::new(hash).unwrap_unchecked();
			let response = CString::new(response).unwrap_unchecked();
			let result = crypt(response.as_ptr(), hash.as_ptr());
			let result = CStr::from_ptr(result).to_str().unwrap_unchecked();
			result == hash.to_str().unwrap_unchecked()
		}
	}
}

pub mod command {
	use std::collections::VecDeque;
	
	use getopt::Opt;
	
	#[derive(Debug)]
	pub enum Command {
		Execute (Execute),
		Deauth,
	}
	
	#[derive(Debug)]
	pub struct Execute {
		pub interactive: bool,
		pub config_file: Option<String>,
		pub user: String,
		pub cmd: Option<String>,
		pub args: Vec<String>,
	}
	
	impl Command {
		pub fn new() -> Self {
			Self::new_from(std::env::args())
		}
		
		pub fn new_from(args: impl Iterator<Item = String>) -> Self {
			let mut exec_cmd = Execute {
				interactive: true,
				config_file: None,
				user: "root".into(),
				cmd: None,
				args: Vec::new(),
			};
			let mut deauth = false;
			
			let mut args: Vec<_> = args.collect();
			let mut opts = getopt::Parser::new(&args, "LnsC:u:h");
			
			let mut exec_shell = false;
			loop {
				match opts.next() {
					None => break,
					Some(result) => match result {
						Ok(opt) => match opt {
							Opt('L', None) => deauth = true,
							Opt('n', None) => exec_cmd.interactive = false,
							Opt('s', None) => exec_shell = true,
							Opt('C', Some(arg)) => exec_cmd.config_file = Some(arg.clone()),
							Opt('u', Some(arg)) => exec_cmd.user = arg.clone(),
							Opt('h', None) => Self::print_help_and_exit(0),
							_ => unreachable!(),
						},
						Err(e) => {
							eprintln!("{}", e.to_string());
							Self::print_help_and_exit(1);
						},
					},
				}
			}
			
			let mut cmd_args = VecDeque::from(args.split_off(opts.index()));
			
			if cmd_args.is_empty() {
				if !exec_shell {
					Self::print_help_and_exit(1);
				}
			} else {
				exec_cmd.cmd = Some(cmd_args.pop_front().unwrap());
				exec_cmd.args = Vec::from(cmd_args);
			}
			
			let command: Command;
			if deauth {
				command = Command::Deauth;
			} else {
				command = Command::Execute(exec_cmd);
			}
			
			command
		}
		
		fn print_help_and_exit(code: i32) -> ! {
			let name = std::env::args().next().unwrap();
			eprintln!("usage: {name} [-Lns] [-C config] [-u user] command [args]");
			std::process::exit(code);
		}
	}
	
	pub fn print_error_and_exit(msg: &str, code: i32) -> ! {
		let name = std::env::args().next().unwrap();
		eprintln!("{name}: {}", msg);
		std::process::exit(code);
	}
}

pub mod config {
	use std::collections::HashMap;
	
	#[derive(Clone, Debug)]
	pub enum RuleAction {
		Permit,
		Deny,
	}
	#[derive(Clone, Debug)]
	pub struct RuleOpts {
		pub nopass: bool,
		pub nolog: bool,
		pub persist: bool,
		pub keepenv: bool,
		pub setenv: Option<HashMap<String, String>>,
	}
	#[derive(Clone, Debug)]
	pub enum RuleIdentity {
		User (String),
		Group (String),
	}
	
	#[derive(Clone, Debug)]
	pub struct Rule {
		pub action: RuleAction,
		pub options: RuleOpts,
		pub identity: RuleIdentity,
		pub target: Option<String>,
		pub command: Option<String>,
		pub args: Option<Vec<String>>,
	}
	
	#[derive(Clone, Debug)]
	pub struct Rules {
		pub allowed: Vec<Rule>,
		pub denied: Vec<Rule>,
	}
	
	impl Rules {
		pub fn r#match<'a>(&self,
			user: &str,
			groups: &'a [impl AsRef<str>],
			cmd: &str,
			args: &'a [impl AsRef<str>],
			target: &str,
		) -> Option<RuleOpts> {
			let match_rules = |rules: &[Rule]| -> Option<RuleOpts> {
				let mut matched: Option<&Rule> = None;
				for rule in rules {
					match &rule.identity {
						RuleIdentity::User(rule_user) => if rule_user != user {
							continue;
						},
						RuleIdentity::Group(group) => if !groups.iter().any(|x| x.as_ref() == group) {
							continue;
						},
					}
					if let Some(rule_cmd) = &rule.command {
						if rule_cmd != cmd {
							continue;
						}
					}
					if let Some(rule_args) = &rule.args {
						if rule_args.len() != args.iter().count() {
							continue;
						}
						if !rule_args.iter().zip(args).all(|(x, y)| x == y.as_ref()) {
							continue;
						}
					}
					if let Some(rule_target) = &rule.target {
						if rule_target != target {
							continue;
						}
					}
					matched = Some(rule);
				}
				match matched {
					Some(rule) => Some(rule.options.clone()),
					None => None,
				}
			};
			let matched = match_rules(&self.allowed);
			if matched.is_some() && match_rules(&self.denied).is_none() {
				matched
			} else {
				None
			}
		}
	}
	
	impl TryFrom<&str> for Rules {
		type Error = String;
		
		fn try_from(config: &str) -> Result<Self, Self::Error> {
			const DEFAULT_RULE: Rule = Rule {
				action: RuleAction::Deny,
				options: RuleOpts {
					nopass: false,
					nolog: false,
					persist: false,
					keepenv: false,
					setenv: None,
				},
				identity: RuleIdentity::User(String::new()),
				target: None,
				command: None,
				args: None,
			};
			
			let mut rules = Rules {
				allowed: Vec::new(),
				denied: Vec::new(),
			};
			
			enum Expect {
				Permission,
				OptionOrIdentity,
				Etc,
			}
			
			let mut tokens = Tokenizer::new(config);
			let mut state = Expect::Permission;
			let mut new_rule = false;
			let mut rule: Rule = DEFAULT_RULE.clone();
			let mut push_rule = |rule: &mut Rule| {
				let value = std::mem::replace(rule, DEFAULT_RULE.clone());
				match value.action {
					RuleAction::Permit => rules.allowed.push(value),
					RuleAction::Deny => rules.denied.push(value),
				};
			};
			while let Some((token, pure)) = tokens.next() {
				if new_rule {
					rule = DEFAULT_RULE.clone();
					state = Expect::Permission;
					new_rule = false;
				}
				match state {
					Expect::Permission => {
						if pure {
							if token == "permit" {
								rule.action = RuleAction::Permit;
							} else if token == "deny" {
								rule.action = RuleAction::Deny;
							} else {
								return Err(format!("Invalid action: {token}"));
							}
						} else {
							return Err(format!("Action must be a keyword!"));
						}
						state = Expect::OptionOrIdentity;
					},
					Expect::OptionOrIdentity => {
						match (&*token, pure) {
							("nopass", true) => rule.options.nopass = true,
							("nolog", true) => rule.options.nolog = true,
							("persist", true) => rule.options.persist = true,
							("keepenv", true) => rule.options.keepenv = true,
							("setenv", true) => rule.options.setenv = Some(parse_env(&mut tokens)?),
							_ => {
								rule.identity = if token.starts_with(':') {
									RuleIdentity::Group(token[1..].into())
								} else {
									RuleIdentity::User(token.into())
								};
								state = Expect::Etc;
							},
						}
					},
					Expect::Etc => {
						match &*token {
							"as" => {
								match tokens.next() {
									Some((target, _)) => rule.target = Some(target.into()),
									None => return Err(format!("Target is specified but missing!")),
								}
							},
							"cmd" => {
								match tokens.next() {
									Some((cmd, _)) => rule.command = Some(cmd.into()),
									None => return Err(format!("Command is specified but missing!")),
								}
							},
							"args" => {
								let mut args: Vec<String> = Vec::new();
								while !tokens.line_ended {
									match tokens.next() {
										Some((arg, _)) => args.push(arg),
										None => break,
									}
								}
								rule.args = Some(args);
							},
							_ => return Err(format!("Unexpected token: {token}")),
						}
					},
				}
				if tokens.line_ended {
					push_rule(&mut rule);
					new_rule = true;
				}
			}
			
			if !new_rule {
				// Push the leftover rule (happens when config doesn't end with a NL)
				push_rule(&mut rule);
			}
			
			return Ok(rules);
			
			fn parse_env<'a>(tokens: &mut Tokenizer<'a>) -> Result<HashMap<String, String>, String> {
				let mut env = HashMap::new();
				let mut ended = false;
				while let Some((token, _)) = tokens.next() {
					let mut token = &*token;
					if token.starts_with('{') {
						token = &token[1..];
						if token.is_empty() {continue;}
					}
					if token.ends_with('}') {
						ended = true;
						if token == "}" {
							break;
						}
						token = &token[..token.len() - 1];
					}
					match token.split_once('=') {
						Some((var, value)) => env.insert(var.into(), value.into()),
						None => env.insert(token.into(), "".into()),
					};
					if ended {break;}
				}
				if ended {
					Ok(env)
				} else {
					Err(format!("Environment is incomplete!"))
				}
			}
			
			struct Tokenizer<'a> {
				#[allow(dead_code)]
				input: &'a str,
				iterator: std::str::Chars<'a>,
				line_ended: bool,
			}
			
			impl<'a> Tokenizer<'a> {
				fn new(config: &'a str) -> Self {
					Tokenizer {
						input: config,
						iterator: config.chars(),
						line_ended: true,
					}
				}
				
				#[allow(unused)]
				fn reset(&mut self) {
					self.iterator = self.input.chars();
					self.line_ended = true;
				}
			}
			
			impl<'a> Iterator for Tokenizer<'a> {
				type Item = (String, bool);
				
				fn next(&mut self) -> Option<Self::Item> {
					let mut token = String::new();
					self.line_ended = false;
					let mut quote = false;
					let mut escape = false;
					let mut pure = true;
					while let Some(chr) = self.iterator.next() {
						if escape {
							token.push(chr);
							escape = false;
							continue;
						}
						match chr {
							'#' => {
								while self.iterator.next().unwrap_or('\n') != '\n' {};
								if !token.is_empty() {
									self.line_ended = true;
									break;
								};
							},
							'"' => {
								pure = false;
								quote = !quote;
							},
							' ' => if quote {
								token.push(chr)
							} else {
								if !token.is_empty() {
									break;
								}
							},
							'\\' => {
								pure = false;
								escape = true;
							},
							'\n' => if !token.is_empty() {
								self.line_ended = true;
								break;
							},
							_ => token.push(chr),
						}
					}
					
					if token.is_empty() {
						None
					} else {
						Some((token, pure))
					}
				}
			}
		}
	}
}
