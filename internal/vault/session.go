package vault

import "sync"

type Session struct {
	Active    bool
	VaultPath string
	VaultID   string

	KIndex    []byte // 32
	KBlobRoot []byte // 32

	Mutex sync.RWMutex
}

func (s *Session) LockAndWipe() {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	if s.KIndex != nil {
		for i := range s.KIndex {
			s.KIndex[i] = 0
		}
		s.KIndex = nil
	}
	if s.KBlobRoot != nil {
		for i := range s.KBlobRoot {
			s.KBlobRoot[i] = 0
		}
		s.KBlobRoot = nil
	}
	s.Active = false
	s.VaultID = ""
	s.VaultPath = ""
}
