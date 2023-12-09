# rsudoas

rsudoas is a reimplementation of doas from BSD made for Linux, though it might work in other *nix platforms.

It aims to be a secure and fast drop-in replacement written in Rust, with potential cross-platform support in the future.

Additionally a built-in shim is planned for sudo to ease migration from sudo to doas.

### Name

`rsudoas` is the name of the primary command for this project, it can be broken into these parts:

* `rs` - Signifies that this is written in Rust.
* `u` - Ultimate, as-in the only privilege escalation tool you'll need.
* `doas` - A reference to the original doas.
* `sudo` - A "hidden" reference to the planned sudo shim.

## Security

If you find any security issues or have related concerns, please consider contacting me privately via [e-mail](mailto:TheDcoder@protonmail.com).

## Acknowledgements

Thanks to all of the authors of the crates on which this project depends on!

Special thanks to [Duncaen](https://github.com/Duncaen) for his fork of OpenDoas, it was heavily used as a reference during the initial development. It was also the first reason why I started this project when I found a "[bug](https://github.com/Duncaen/OpenDoas/issues/117)".  P.S. @Duncaen I'm still waiting for you to accept my [pull request](https://github.com/Duncaen/OpenDoas/pull/119) to fix that!

Thanks to the people in `##rust` at [Libera Chat](https://libera.chat/) who helped me paitently to my sometimes overly enthusiastic line of enquiry.

And finally, thanks to [sylvestre](https://github.com/sylvestre) who [got me started](https://mastodon.social/@TheDcoder/110559205641655915) with Rust in the first place a few months back when I stumbled across a [bug in uutils](https://github.com/uutils/coreutils/issues/4981).
