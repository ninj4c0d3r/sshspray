# SSH Spray Tool

A high-performance SSH spray tool using `github.com/melbahja/goph`, supporting password and key authentication, combo lists, CIDR or single IPs, concurrency control, and timeouts.

## Features

- Supports password and SSH key authentication
- Accepts usernames and passwords via files or single values
- Supports combo files (`username:password`) with custom delimiter
- Accepts targets as individual IPs, hostnames, or CIDR ranges
- Optional jitter between attempts to evade rate-limiting
- Fully concurrent with configurable thread pool (`--threads`)
- Configurable connection timeout per target
- Verbose logging with optional failure reason output
- Cross-platform support (Linux, macOS, Windows)

## Requirements

- Go 1.18+
- Linux, macOS, or Windows

---

## Installation

Clone this repository and install dependencies:

```bash
git clone https://github.com/ninj4c0d3r/sshspray.git
cd sshspray
go mod tidy
```

You can run the tool directly using:

```bash
go run main.go [options]
```

To build a binary:

```bash
go build -o sshspray main.go
```

---

## Usage

```bash
go run main.go [OPTIONS]
```

### Authentication Options

| Option                   | Description                                       |
|--------------------------|---------------------------------------------------|
| `-u`, `--user`           | Single username                                   |
| `-U`, `--userfile`       | File with list of usernames                       |
| `-p`, `--password`       | Single password                                   |
| `-P`, `--passfile`       | File with list of passwords                       |
| `-C`, `--combo-file`     | File with `username:password` combos              |
| `-d`, `--delimiter`      | Delimiter used in combo file (default: `:`)      |
| `-i`, `--key-file`       | Path to private key file                          |
| `-s`, `--passphrase`     | Passphrase for private key                        |

### Target Options

| Option                   | Description                                       |
|--------------------------|---------------------------------------------------|
| `-t`, `--target`         | Single IP or hostname                             |
| `-T`, `--targetfile`     | File with list of IPs and/or CIDRs                |

### Execution Options

| Option                   | Description                                       |
|--------------------------|---------------------------------------------------|
| `-q`, `--threads`        | Number of concurrent threads (default: 10)       |
| `-w`, `--wait`           | Timeout per connection in seconds (default: 5)   |
| `--jmin`                 | Minimum jitter delay in milliseconds (default: 0)  |
| `--jmax`                 | Maximum jitter delay in milliseconds (default: 0)  |
| `-v`                     | Verbose output: `-v` for failures, `-vv` for reasons |

---

## Examples

### 1. Using a combo list (recommended)

```bash
go run main.go -C combos.txt -T targets.txt -q 20 -v
```

Example `combos.txt`:

```
admin:admin123
user:test123
```

### 2. Using separate user and password files

```bash
go run main.go -U users.txt -P passwords.txt -T targets.txt -q 30
```

### 3. Single target, user and password

```bash
go run main.go -u root -p 123456 -t 192.168.1.10
```

### 4. Using SSH key with CIDR expansion

```bash
go run main.go -U users.txt -i ~/.ssh/id_rsa -s mypass -T 192.168.1.0/28
```

---
## Disclaimer

This tool is provided strictly for authorized security assessments and educational purposes. Unauthorized use may violate laws and ethical guidelines.
