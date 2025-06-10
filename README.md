# CLI Snitch

A macOS network connection monitor and firewall manager for the terminal. CLI Snitch monitors outbound network connections and allows you to control which applications can access the internet.

## Features

- Real-time monitoring of outbound network connections
- Interactive prompts for allowing or denying connections
- Persistent rule management with JSON storage
- pfctl firewall integration for blocking connections
- Performance optimization with connection caching
- Detailed logging and error handling

## Installation

### Via Homebrew (Recommended)

```bash
# Add the tap
brew tap yourusername/tap

# Install CLI Snitch
brew install cli-snitch
```

### Via GitHub Releases

1. Download the latest release for your architecture from [GitHub Releases](https://github.com/yourusername/cli-snitch/releases)
2. Extract the binary:
   ```bash
   tar -xzf cli-snitch-v1.0.0-darwin-amd64.tar.gz
   ```
3. Move to your PATH:
   ```bash
   sudo mv cli-snitch /usr/local/bin/
   chmod +x /usr/local/bin/cli-snitch
   ```

### Build from source

```bash
git clone https://github.com/yourusername/cli-snitch
cd cli-snitch
make build
# Or manually:
# go build -o cli-snitch ./cmd/cli-snitch
```

### Prerequisites

- macOS (tested on macOS Sonoma and later)
- Root privileges (required for network monitoring and firewall management)
- Go 1.19+ (only needed if building from source)

## Usage

### Start monitoring

```bash
sudo ./cli-snitch watch
```

This starts real-time monitoring of outbound connections. When a new connection is detected, you'll see a prompt like:

```
🚨 New Outbound Connection Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📱 Application: Google Chrome
  🆔 Process ID: 1234
  👤 User: nick
  🌐 Destination: example.com:443
  🔌 Protocol: TCP
  📍 Local: 192.168.1.100:54321
  🏷️  Host Info: External Server

? What would you like to do with this connection?
> ✅ Allow Once
  🔁 Allow Always  
  ❌ Deny Once
  🚫 Deny Always
```

### Manage rules

List existing rules:
```bash
./cli-snitch list-rules
```

Clear all rules:
```bash
./cli-snitch clear-rules
```

### Firewall management

Check firewall status:
```bash
sudo ./cli-snitch firewall-status
```

List active firewall rules:
```bash
sudo ./cli-snitch list-firewall
```

Clean up expired rules:
```bash
sudo ./cli-snitch firewall-cleanup
```

Monitor firewall status in real-time:
```bash
sudo ./cli-snitch firewall-monitor
```

### System status

Check system integration status:
```bash
./cli-snitch system-status
```

### Performance benchmarking

Run performance tests:
```bash
./cli-snitch benchmark load 100 30s
./cli-snitch benchmark memory 1000 60s
./cli-snitch benchmark full-suite
```

## Configuration

CLI Snitch stores its configuration and rules in `~/.cli-snitch/`:

- `rules.json` - Persistent connection rules
- `logs/` - Application logs (when file logging is enabled)

## How it works

1. **Connection Detection**: Uses `lsof` to monitor network connections in real-time
2. **Rule Matching**: Checks new connections against saved rules
3. **User Interaction**: Prompts for decisions on unknown connections
4. **Firewall Integration**: Applies deny rules using macOS pfctl
5. **Rule Persistence**: Saves decisions for future connections

## Security

- Requires root privileges for network monitoring and firewall management
- Uses pfctl anchors to avoid conflicts with system firewall rules
- Implements proper cleanup of firewall rules on exit
- All firewall rules are isolated in the `cli-snitch` anchor

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

This project is for educational and personal use. For production network security, consider commercial solutions like Little Snitch.

## Acknowledgments

Inspired by Little Snitch for providing excellent network monitoring on macOS. 