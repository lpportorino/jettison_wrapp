# Wrapp - Redis Process Wrapper for NVIDIA Orin

A high-performance process wrapper optimized for NVIDIA Orin AGX (Cortex-A78AE) that streams application output to Redis with advanced features like crash detection, core dump analysis, and multi-line log handling.

## 🎯 Target Platform

This tool is specifically optimized for:
- **NVIDIA Jetson AGX Orin 32GB**
- **CPU**: Cortex-A78AE (12-core ARM v8.2 64-bit CPU, 3MB L2 + 6MB L3)
- **Architecture**: ARMv8.2-A with Crypto Extensions and LSE (Large System Extensions)

## Overview

Wrapp is a Go-based process wrapper designed to execute and monitor applications while streaming their output to Redis. Originally part of the Jettison project, it has been extracted and optimized specifically for NVIDIA Orin platforms.

## Key Features

- **Redis Streaming**: Real-time stdout/stderr streaming to Redis
- **Crash Detection**: Automatic core dump detection and GDB analysis
- **Multi-line Support**: Handles multi-line logs with special delimiters
- **User Switching**: Can run processes as different users (when run as root)
- **Health Monitoring**: Continuous Redis connection monitoring
- **Metadata Extraction**: Parses special markers in output for metrics
- **Session Management**: Tracks process runs with start/end markers
- **Orin Optimization**: Built with ARM64 v8.2 + crypto + LSE extensions

## Architecture

### Redis Database Usage

- **DB 1 (Logs)**: Stores application logs in Redis Streams
- **DB 2 (Values)**: Stores extracted metrics and key-value pairs
- **DB 5 (Config)**: Used for configuration and control

### Stream Structure

Logs are organized in Redis Streams using the configurable `stream_name`:
- `logs:app:<stream_name>:info` - Standard output logs
- `logs:app:<stream_name>:status` - Status messages and run markers
- `logs:app:<stream_name>:error` - Error messages
- `logs:app:<stream_name>:crash` - Crash reports and backtraces

## Installation

### Prerequisites

- Go 1.23 or later (for building from source)
- Redis server
- GDB (optional, for core dump analysis)
- NVIDIA Jetson AGX Orin (target platform)

### Building from Source

#### On NVIDIA Orin (Native Build)

```bash
# Clone the repository
git clone https://github.com/yourusername/wrapp.git
cd wrapp

# Download dependencies
make deps

# Build release version (no debug output)
make release

# Or build debug version (with debug output)
make dev

# Install to system
sudo make install          # Installs release version
sudo make install-dev      # Installs debug version
```



## Configuration

Wrapp now reads all configuration from a single TOML file:

```toml
[redis]
host = "localhost"
port = 6379
password = "your_redis_password"

[app]
# The executable to run
executable = "/usr/local/bin/myservice"

# Arguments to pass to the executable
args = ["--config", "/etc/myservice.conf", "--verbose"]

# User to run the process as (only when wrapp runs as root)
user = "serviceuser"

# Name for Redis streams (logs:app:<stream_name>:*)
# Defaults to executable base name if not specified
stream_name = "myservice"
```

## Usage

### Basic Usage

```bash
wrapp <config.toml>
```

That's it! Everything is configured in the TOML file.

### Examples

See the `examples/` directory for sample configurations:

- `config.example.toml` - Full example with all options
- `python-script.toml` - Running a Python script
- `system-service.toml` - Monitoring a system service
- `simple-command.toml` - Simple command execution

```bash
# Run with a configuration file
wrapp config.toml

# Run as root to switch users
sudo wrapp service-config.toml
```

### Advanced Features

#### Multi-line Log Handling

Use special delimiters for multi-line logs:
```
Normal log line
>>|Start of multi-line
content spans
multiple lines|<<
Another normal line
```

#### Metric Extraction

Embed special markers in output:
```
{{counter}}        # Increment a counter
{{value:42}}       # Set a specific value
```

Stored in Redis DB 2: `wrapp:<stream_name>:<key>`

#### Core Dump Analysis

Enable core dumps before running:
```bash
ulimit -c unlimited
echo "/tmp/core-%E-%t-%p-%s" | sudo tee /proc/sys/kernel/core_pattern
```

## Build System

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make release` | Build production version (no debug output) |
| `make dev` | Build debug version (with debug logging) |
| `make build` | Alias for `make release` |
| `make install` | Install release version to `/usr/local/bin` |
| `make install-dev` | Install debug version to `/usr/local/bin` |
| `make clean` | Remove build artifacts |
| `make deps` | Update Go dependencies |
| `make test` | Run tests |
| `make help` | Show all available targets |

### Debug vs Release Builds

- **Release Build** (`make release`):
  - No debug output
  - Optimized binary size (~5.2MB)
  - Production use

- **Debug Build** (`make dev`):
  - Timestamped debug output to stderr
  - Shows configuration, arguments, user switching, etc.
  - Larger binary size (~7.7MB)
  - Development and troubleshooting

Debug output format: `[DEBUG HH:MM:SS.mmm] Message`

### Build Optimization Details

The Orin build uses:
- `GOOS=linux` - Linux operating system
- `GOARCH=arm64` - 64-bit ARM architecture
- `GOARM64=v8.2,crypto,lse` - ARMv8.2-A with cryptographic and LSE extensions
- `-trimpath` - Remove file system paths from binary
- `-s -w` - Strip debug information for smaller binary


## Performance Considerations

### Orin-Specific Optimizations

1. **LSE (Large System Extensions)**: Improves atomic operations performance
2. **Crypto Extensions**: Hardware-accelerated cryptography
3. **Memory Ordering**: Optimized for ARM64 memory model
4. **Trimmed Binaries**: Smaller size for faster loading

### Redis Performance

- Streams are capped at 1000 entries with approximate trimming
- Pipeline operations for batch writes
- Separate connections for logs, values, and config
- 60-second keep-alive pings

## Development

### Project Structure

```
.
├── wrapp.go                 # Main source code
├── debug_on.go              # Debug logging implementation (debug builds)
├── debug_off.go             # No-op logging (release builds)
├── examples/                # Example configuration files
│   ├── python-script.toml
│   ├── system-service.toml
│   └── simple-command.toml
├── build/                   # Build output directory
├── config.example.toml      # Full configuration example
├── go.mod                   # Go module definition
├── go.sum                   # Dependency checksums
├── Makefile                 # Build automation
└── README.md                # This file
```

### Testing on Different Platforms

```bash
# Test on Orin (native)
make test

# Test locally (builds for current architecture)
go build -o build/wrapp-local .
./build/wrapp-local config.toml
```

### Debugging

```bash
# Build debug version with logging enabled
make dev

# Run debug version to see detailed output
./build/wrapp-debug config.toml

# Debug output includes:
# - Configuration loading and values
# - Redis connection attempts
# - User determination logic
# - Process execution details (PID, exit code)
# - Command construction
```

## Troubleshooting

### Common Issues

#### Redis Connection Failed
```bash
# Check Redis status
systemctl status redis
redis-cli ping

# Verify configuration
cat config.toml
```

#### Core Dumps Not Generated
```bash
# Check ulimits
ulimit -c

# Set unlimited
ulimit -c unlimited

# Verify core pattern
cat /proc/sys/kernel/core_pattern
```

#### Binary Architecture Mismatch
```bash
# Verify binary architecture
file wrapp
# Should show: ELF 64-bit LSB executable, ARM aarch64

# Check Go build info
go version -m wrapp
```

## Performance Metrics

On NVIDIA Orin AGX 32GB:
- Startup time: <10ms
- Memory usage: ~10MB baseline
- CPU usage: <1% idle, scales with log volume
- Log throughput: >100k lines/second
- Latency: <1ms Redis write

## License

This tool was extracted from the Jettison project. Please refer to the original project for licensing information.

## Support

For issues, feature requests, or questions:
1. Check the [Issues](https://github.com/yourusername/wrapp/issues) page
2. Review existing documentation
3. Create a new issue with detailed information

## Credits

Originally developed as part of the Jettison project's Redis logging infrastructure, optimized for NVIDIA Orin AGX platforms.