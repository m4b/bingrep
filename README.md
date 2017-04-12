# bingrep

Greps through binaries from various OSs and architectures, and colors them. Current backends:

* ELF 32/64, arm, x86, openrisc - all others will parse and color, but relocations won't show properly
* Mach 32/64, arm, x86
* PE (debug only)

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
