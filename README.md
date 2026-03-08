# 0x4E4558vault

A cryptographic vault application built with Go, providing secure file storage and management through a graphical interface.

## Features

- **Secure Encryption**: Uses XChaCha20-Poly1305 AEAD encryption with HKDF key derivation
- **Password-Based Authentication**: Argon2id key derivation with configurable parameters
- **Chunked Storage**: Files are encrypted and stored in 1MiB chunks for efficient handling
- **GUI Framework**: Built with Fyne v2 (cross-platform support planned)
- **Atomic Operations**: All file operations are atomic to prevent data corruption
- **Version Control**: Each file update increments a generation number for tracking

## Security Design

### Encryption
- **Algorithm**: XChaCha20-Poly1305 AEAD
- **Key Derivation**: HKDF-SHA256 for subkey derivation
- **Password KDF**: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
- **Nonce Management**: 24-byte nonces with counter-based chunk sequencing

### Vault Structure
```
vault/
├── vault.hdr          # Encrypted vault header with KDF parameters
├── keyslot.nexk       # Encrypted vault master key
├── index.nexi         # Encrypted file index
└── .nex/blobs/       # Encrypted file blobs
    └── xx/            # First two hex digits of blob ID
        └── {id}.nex   # Individual encrypted file
```

## Building

### Prerequisites
- Go 1.26.1 or later
- Currently tested on macOS (Linux and Windows support planned)

### Build Commands
```bash
# Build the application
go build -o nexvault main.go

# Run tests
go test ./...

# Build all packages
go build ./...
```

## Usage

### Creating a New Vault
1. Launch the application
2. Click "Link Vault Folder" and select a directory
3. Enter a strong password
4. Click "Create" to initialize the vault

### Unlocking an Existing Vault
1. Link to the vault directory
2. Enter the vault password
3. Click "Unlock" to access vault operations

### Vault Operations
- **Import New**: Add files to the vault
- **Replace**: Update existing files with new versions
- **Import Directory**: Bulk import entire directory structures
- **Browse Index**: View and manage vault contents
- **Decrypt**: Export files from the vault

## Configuration

### Default KDF Parameters
- **Memory**: 256 MiB (configurable up to 512 MiB)
- **Iterations**: 3 (configurable up to 4)
- **Parallelism**: Number of CPU cores (max 4)

### File Handling
- **Chunk Size**: 1 MiB (fixed for performance)
- **Blob Format**: Version 2 with authenticated encryption
- **Index Encryption**: Separate AEAD key derived from vault master key

## Development

### Project Structure
```
nexvault/
├── cmd/
│   └── nexvault/
│       ├── main.go              # Application entry point
│       └── ui/                 # GUI implementation
├── internal/
│   ├── crypto/                # Cryptographic operations
│   ├── nex/                  # Core constants and utilities
│   └── vault/                # Vault logic and operations
├── go.mod                    # Go module definition
└── main.go                   # Build entry point
```

### Key Components
- **Vault**: Main vault operations (create, unlock, manage)
- **Crypto**: Key derivation and encryption utilities
- **NEX**: Core constants, file I/O, and utilities
- **UI**: Fyne-based graphical interface

## Security Considerations

- Passwords are never stored in plain text
- All sensitive memory is wiped when no longer needed
- File operations use atomic writes to prevent corruption
- Vault master keys are encrypted with derived keys
- Each file chunk is individually authenticated

## License

Proprietary software. All rights reserved.

## Dependencies

- [fyne.io/fyne/v2](https://fyne.io/) - Cross-platform GUI framework
- [golang.org/x/crypto](https://golang.org/x/crypto) - Cryptographic primitives

## System Requirements

- **Memory**: Minimum 512 MiB RAM (1 GiB recommended)
- **Storage**: Space for encrypted files plus overhead
- **OS**: Currently macOS 10.15+ (Linux and Windows support planned)
