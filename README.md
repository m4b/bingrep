# bingrep

Greps through binaries from various OSs and architectures, and colors them. Current backends:

* ELF 32/64, arm, x86, openrisc - all others will parse and color, but relocations won't show properly
* Mach 32/64, arm, x86
* PE (debug only)

**NOTE**: Requires rustc version 1.15 or greater.  If you're using a distro's rust compiler, consider using https://rustup.rs to install your rustc compiler and associated binaries.

![pic2](etc/s2.png)

![pic1](etc/s1.png)

![mach](etc/mach.png)

## Build

cargo build --release

## Run

Example:

```
bingrep /bin/ls
```

To dump internal debug representation of the parsed binary:

```
bingrep -d /bin/ls
```
