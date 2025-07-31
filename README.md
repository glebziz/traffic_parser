# Traffic Parser

[![Test](https://github.com/glebziz/traffic_parser/actions/workflows/test.yml/badge.svg)](https://github.com/glebziz/traffic_parser/actions/workflows/test.yml)
[![Lint](https://github.com/glebziz/traffic_parser/actions/workflows/lint.yml/badge.svg)](https://github.com/glebziz/traffic_parser/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/glebziz/traffic_parser/graph/badge.svg?token=571RKHZFFP)](https://codecov.io/gh/glebziz/traffic_parser)

A light-weight network traffic analysis tool.

## Features

- Real-time packet capture and analysis
- TLS/SSL traffic inspection
- Connection tracking and monitoring
- Integration with nftables for
- Optional debug HTTP server for monitoring

## Requirements

- Rust 2024 edition or later
- Linux environment with nftables support
- Network interface with promiscuous mode capability
- Root/sudo privileges (for packet capture and netfilter operations)

## Installation

### From Source

1. Clone the repository:
   ```
   git clone https://github.com/glebziz/traffic_parser
   cd traffic_parser
   ```

2. Build the project:
   ```
   cargo build --release
   ```

3. The compiled binary will be available at `target/release/traffic_parser`

## Configuration

The application uses a YAML configuration file (default: `config.yaml` in the current directory). You can specify a different configuration file using the `-c` or `--config` command-line option.

## Usage

### Basic Usage

Run the application with the default configuration:

```bash
sudo ./traffic_parser
```

### Specify Configuration File

```bash
sudo ./traffic_parser --config /path/to/config.yaml
```

### Enable Debug Mode

```bash
sudo ./traffic_parser --debug
```

This starts a debug HTTP server (default port: 55555) that provides information about tracked connections.

## License

[MIT](https://choosealicense.com/licenses/mit/)