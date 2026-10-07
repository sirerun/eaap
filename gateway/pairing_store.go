package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type pairingState struct {
	Version     int                        `json:"version"`
	Consumed    map[string]SessionIdentity `json:"consumed"`
	Generations map[string]SessionIdentity `json:"generations"`
}
type pairingStore struct{ root string }

func newPairingStore(root string) (*pairingStore, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("pairing state root must be an absolute configured path")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create pairing state root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("pairing state root must be a private non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(root) != resolved {
		return nil, fmt.Errorf("pairing state root must resolve without symlinks")
	}
	return &pairingStore{root: root}, nil
}
func (s *pairingStore) consume(token string, c PairingCredential) error {
	digest := sha256.Sum256([]byte(token))
	id := hex.EncodeToString(digest[:])
	lockPath := filepath.Join(s.root, "pairing.lock")
	if info, e := os.Lstat(lockPath); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("pairing lock permissions or type are invalid")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := filepath.Join(s.root, "pairing.json")
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("pairing state file permissions or type are invalid")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	state := pairingState{Version: 1, Consumed: map[string]SessionIdentity{}, Generations: map[string]SessionIdentity{}}
	if raw, e := os.ReadFile(path); e == nil {
		if json.Unmarshal(raw, &state) != nil || state.Version != 1 || state.Consumed == nil || state.Generations == nil {
			return fmt.Errorf("pairing state corrupt")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, ok := state.Consumed[id]; ok {
		return fmt.Errorf("pairing token already consumed")
	}
	key := c.TenantID + "\x00" + c.AccountID + "\x00" + c.Provider
	identity := SessionIdentity{c.TenantID, c.AccountID, c.Provider, c.ConnectionID, c.Generation}
	if prev, ok := state.Generations[key]; ok && (identity.Generation <= prev.Generation || identity.ConnectionID == prev.ConnectionID) {
		return fmt.Errorf("stale or reused pairing generation")
	}
	if !c.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("pairing token expired")
	}
	state.Consumed[id] = identity
	state.Generations[key] = identity
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, ".pairing-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
