# WoL-go
A tool for controlling and implementing Wake-on-LAN (WoL) from a web interface.

## Overview
WoL-go is a utility designed to enable remote wake-up of machines through a user-friendly web interface. This tool is ideal for deployment on a router or any always-on machine within your local area network (LAN). It supports remote access via internal network penetration techniques or IPv6, making it possible to manage and wake your machines from anywhere.

## Features
- **Web-based Interface**: Easy to use and accessible from a browser.
- **Cross-platform Support**: Binaries available for multiple operating systems and architectures.
- **Remote Accessibility**: Manage wake-up functionality through internal network penetration or IPv6.

## Getting Started

### Prerequisites
To use WoL-go, you will need:
- A machine that is always on within your LAN, such as a router.
- [Go installed](https://golang.org/dl/) if you plan to compile the project yourself.

### Download
You can directly download the pre-compiled binaries suited for your system architecture from the [Releases page](https://github.com/yourusername/WoL-go/releases).

### Compilation
If you prefer to compile the binary yourself, use the following commands adjusted for your target operating system and architecture:

```bash
# For Linux amd64
GOOS=linux GOARCH=amd64 go build -o WoL-go main.go

# Example for Windows amd64
GOOS=windows GOARCH=amd64 go build -o WoL-go.exe main.go
```

### Running the Server
To start the service, run the following command:

```bash
./WoL-go
```

Then, access the web interface by navigating to `http://localhost:9543` in your web browser.

## Usage
Once WoL-go is running, you can add the MAC addresses of the machines you want to be able to wake up. Use the web interface to manage these addresses and initiate the wake-up command.

## Contributing
Contributions are welcome! Feel free to open pull requests or issues to improve the functionality or documentation of WoL-go.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
