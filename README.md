# bingrep

Greps through binaries from various OSs and architectures, and colors them (for ELF only at the moment).

![pic2](etc/s2.png)

![pic1](etc/s1.png)

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
