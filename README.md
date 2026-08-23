# Proxima

A minimal HTTPS reverse proxy with automatic certificate generation and dynamic routing.

## Features
- **Automatic TLS**: Generates a self-signed CA and server certificate if one isn't provided.
- **HTTP to HTTPS Redirect**: Automatic redirection from port 80 to 443.
- **Dynamic Routing**: Map specific hostnames to different backend destinations via JSON config.
- **Wildcard Support**: Automatically generates wildcard certificates for configured domains.

## Installation
```bash
make
```

## Configuration
Create a `Proxima.json` file in the root directory:

```json
{
  "router": {
    "default_destination": "http://localhost:8080",
    "overrides": [
      {
        "source": "api.local",
        "destination": "http://localhost:3000"
      }
    ]
  },
  "tls": {
    "pem_file": "Proxima.pem",
    "domains": ["local.test", "api.local"]
  }
}
```

## Usage
```bash
# Use default config or PROXIMA_CFG environment variable
export PROXIMA_CFG=Proxima.json
sudo ./proxima
```

*Note: Root privileges are required to bind to ports 80 and 443.*
