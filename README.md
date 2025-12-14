rdpscanner is a tool to check if a port is running RDP service.

# usage
```bash
Usage: rdpscanner [OPTIONS] --inputfile <INPUTFILE>

Options:
  -i, --inputfile <INPUTFILE>
  -r, --rate <RATE>            [default: 100]
  -t, --timeout <TIMEOUT>      [default: 10]
  -v, --verbose
  -h, --help                   Print help
  -V, --version                Print version
```

the input file is a list of ip:port separated by newline:
```
1.2.3.4:345
5.3.5.2:5321
6.2.4.5:6231
```

> [!WARNING]
> This tool is intended for educational purposes and authorized penetration testing only. do not use it against targets or systems without explicit permission from the owner.

# building
clone the repo, cd into it and run `cargo build --release`
