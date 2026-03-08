package vault

type IndexEntry struct {
	VaultRelPath string `json:"path"`
	BlobName     string `json:"blob"`
	Size         int64  `json:"size"`
	Added        int64  `json:"ts"`
	Gen          uint64 `json:"gen"`
}

type VaultIndex struct {
	Entries []IndexEntry `json:"entries"`
}
