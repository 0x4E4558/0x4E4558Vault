package nex

const (
	MB1, MB2, MB3 = 0x4E, 0x45, 0x58 // "NEX"
	AppVersion    = 0x01

	VMKSize       = 64
	NonceSize     = 24
	VaultSaltSize = 32
	BlobSaltSize  = 32

	// Bounded, DoS-resistant KDF policy
	ArgonMemDefaultKiB = 256 * 1024 // 256 MiB
	ArgonMemMaxKiB     = 512 * 1024 // 512 MiB
	ArgonTimeDefault   = 3
	ArgonTimeMax       = 4
	ArgonThreadsMax    = 4

	ChunkSize = 1 << 20 // 1 MiB

	BlobFormatV2 uint8 = 0x02
)
