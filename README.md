# DEHú CLI

A command line client for the Spanish DEHú service (LEMA). This client allows for interacting with the digital notifications and communications system of the Spanish administration.

## Overview

The DEHú (Dirección Electrónica Habilitada única) is the Spanish administration's system for digital notifications. This CLI tool provides a way to:

- List pending notifications
- Access notification content
- Download notification annexes
- Get notification receipts
- List and access already processed notifications

## Requirements

- Java 11 or higher
- X.509 certificate for authentication (required by DEHú)

## Installation

The project uses Clojure CLI tools and deps.edn for dependencies.

```bash
# Clone the repository
git clone https://github.com/nilp0inter/dehucli.git
cd dehucli

# Run directly with Clojure
clj -M:run --help
```

## Usage

Basic usage pattern:

```bash
clj -M:run [options] command [args]
```

### Options

- `-u, --username NIF` - NIF (Spanish Tax ID) for authentication
- `-c, --certificate PATH` - Path to X.509 certificate file
- `-k, --key PATH` - Path to private key file
- `-e, --environment ENV` - Environment: 'se' for testing, 'pro' for production (default: se)
- `-h, --help` - Show help

### Commands

- `localiza` - List pending notifications
- `peticion-acceso ID` - Access a notification content
- `consulta-anexos ID REF` - Get an annex by reference
- `consulta-acuse ID CSV` - Get receipt PDF
- `localiza-realizadas` - List processed notifications
- `consulta-realizadas ID` - Get processed notification content

### Examples

```bash
# List pending notifications
clj -M:run -u 12345678A -c mycert.pem -k mykey.pem localiza

# Access a notification
clj -M:run -u 12345678A -c mycert.pem -k mykey.pem peticion-acceso 1234567890abcdef

# Get an annex document
clj -M:run -u 12345678A -c mycert.pem -k mykey.pem consulta-anexos 1234567890abcdef YmFzZTY0cmVmZXJlbmNl

# Get a receipt PDF
clj -M:run -u 12345678A -c mycert.pem -k mykey.pem consulta-acuse 1234567890abcdef DEHU-1234567890abcdef
```

## Building an Executable JAR

To build a standalone JAR file:

```bash
clj -X:uberjar
```

This will create a file called `dehucli.jar` that can be run with:

```bash
java -jar dehucli.jar [options] command [args]
```

## Development

This project uses devenv with Clojure enabled.

### Running in Development Mode

```bash
clj -M:run [options] command [args]
```

### Project Structure

- `src/dehucli/core.clj` - Main CLI entry point
- `src/dehucli/api.clj` - DEHú API client
- `src/dehucli/security.clj` - Certificate and security handling
- `src/dehucli/PasswordCallback.clj` - WS-Security callback handler

## License

This project is licensed under the terms of the LICENSE file included in the repository.
