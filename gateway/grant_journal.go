package main

// GrantJournal stores replay-resistant observations about signed grants. Its
// records are evidence only: they do not authorize, pace, prepare, or dispatch
// an external effect.
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	grantJournalVersion     = 1
	grantJournalMaxEntries  = 10000
	grantJournalMaxBytes    = 16 << 20
	grantJournalMaxLockWait = 30 * time.Second
)

var (
	ErrGrantReplay      = errors.New("grant journal replay already observed")
	ErrGrantConflict    = errors.New("grant journal binding conflict")
	ErrGrantJournalFull = errors.New("grant journal capacity exhausted")
	ErrGrantVersion     = errors.New("grant journal version conflict")
)

type GrantJournalConfig struct {
	StateRoot   string
	LockTimeout time.Duration
}

type GrantObservationState string

const (
	GrantObserved GrantObservationState = "observation"
	GrantPrepared GrantObservationState = "prepared"
	GrantUnknown  GrantObservationState = "unknown"
	GrantAccepted GrantObservationState = "accepted"
	GrantRejected GrantObservationState = "rejected"
)

// GrantObservation is a non-authorizing evidence record. Digests are used for
// identity; neither compact grants nor credential/private input values persist.
type GrantObservation struct {
	Version       uint64                `json:"version"`
	State         GrantObservationState `json:"state"`
	Issuer        string                `json:"issuer"`
	Tenant        string                `json:"tenant"`
	AttemptDigest string                `json:"attempt_digest"`
	NonceDigest   string                `json:"nonce_digest"`
	TupleDigest   string                `json:"tuple_digest"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type grantJournalState struct {
	Schema  int                         `json:"schema"`
	Entries map[string]GrantObservation `json:"entries"`
	Nonces  map[string]string           `json:"nonces"`
}

type grantJournal struct {
	root        string
	lockTimeout time.Duration
	openFile    func(string, int, os.FileMode) (*os.File, error)
	writeFile   func(string, []byte) error
	writeTemp   func(*os.File, []byte) error
	syncTemp    func(*os.File) error
	renameFile  func(string, string) error
	syncDir     func(string) error
}

// NewGrantJournal opens an existing operator-initialized journal. It never
// creates a root or initializes absent state; loss requires explicit recovery.
func NewGrantJournal(cfg GrantJournalConfig) (*grantJournal, error) {
	j, err := configuredGrantJournal(cfg)
	if err != nil {
		return nil, err
	}
	if err = validateJournalRoot(j.root); err != nil {
		return nil, err
	}
	err = j.withState(context.Background(), func(*grantJournalState) error { return errJournalExisting })
	if err != nil {
		return nil, err
	}
	return j, nil
}

// InitializeGrantJournal is an explicit first-enrollment operation, never an
// ordinary startup fallback. The configured root must not exist. Failures leave
// the owned partial root in place for operator recovery; no automatic reset.
func InitializeGrantJournal(cfg GrantJournalConfig) (_ *grantJournal, retErr error) {
	j, err := configuredGrantJournal(cfg)
	if err != nil {
		return nil, err
	}
	if err = validateJournalPath(j.root, true); err != nil {
		return nil, err
	}
	if err = os.Mkdir(j.root, 0700); err != nil {
		return nil, fmt.Errorf("initialize fresh grant journal root: %w", err)
	}
	if err = validateJournalRoot(j.root); err != nil {
		return nil, err
	}
	parent, err := os.Open(filepath.Dir(j.root))
	if err != nil {
		return nil, err
	}
	if err = errors.Join(parent.Sync(), parent.Close()); err != nil {
		return nil, err
	}
	lock, err := j.acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, syscall.Flock(int(lock.Fd()), syscall.LOCK_UN), lock.Close()) }()
	marker := j.markerBytes(lock)
	if len(marker) == 0 {
		return nil, errors.New("grant journal initialization lock unavailable")
	}
	if err = j.writeFile(filepath.Join(j.root, "initialized"), marker); err != nil {
		return nil, err
	}
	state := grantJournalState{Schema: grantJournalVersion, Entries: map[string]GrantObservation{}, Nonces: map[string]string{}}
	if err = j.writeFile(filepath.Join(j.root, "state.json"), marshalGrantJournal(state)); err != nil {
		return nil, err
	}
	return j, nil
}

func configuredGrantJournal(cfg GrantJournalConfig) (*grantJournal, error) {
	if cfg.StateRoot == "" || !filepath.IsAbs(cfg.StateRoot) {
		return nil, errors.New("grant journal state root must be an operator-configured absolute path")
	}
	if cfg.LockTimeout <= 0 {
		cfg.LockTimeout = 2 * time.Second
	}
	if cfg.LockTimeout > grantJournalMaxLockWait {
		return nil, errors.New("grant journal lock timeout exceeds bounded maximum")
	}
	j := &grantJournal{root: filepath.Clean(cfg.StateRoot), lockTimeout: cfg.LockTimeout, openFile: os.OpenFile}
	j.writeFile = j.atomicWrite
	return j, nil
}

func validateJournalPath(path string, allowMissingLeaf bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("grant journal path is not absolute")
	}
	cur := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), cur), string(filepath.Separator))
	for i, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if os.IsNotExist(err) && allowMissingLeaf && i == len(parts)-1 {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect grant journal path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("grant journal path contains a symlink")
		}
		if i < len(parts)-1 || info.IsDir() {
			if !info.IsDir() {
				return errors.New("grant journal path ancestor is not a directory")
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
				return errors.New("grant journal path ancestor has untrusted ownership")
			}
			stickyRootTemp := st.Uid == 0 && info.Mode()&os.ModeSticky != 0
			if info.Mode().Perm()&0022 != 0 && !stickyRootTemp {
				return errors.New("grant journal path ancestor is writable by group or others")
			}
		} else if !info.IsDir() {
			return errors.New("grant journal root is not a directory")
		}
	}
	return nil
}

func validateJournalRoot(root string) error {
	if err := validateJournalPath(root, false); err != nil {
		return err
	}
	i, err := os.Lstat(root)
	if err != nil {
		return err
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !i.IsDir() || i.Mode().Perm()&0077 != 0 || i.Mode()&os.ModeSetuid != 0 || i.Mode()&os.ModeSetgid != 0 {
		return errors.New("grant journal root must be owned by the effective user and private")
	}
	return nil
}

func (j *grantJournal) Observe(ctx context.Context, compact string, cfg GrantConsumerConfig, binding GrantExecutionBinding, now time.Time) (GrantObservation, bool, error) {
	if err := ctx.Err(); err != nil {
		return GrantObservation{}, false, err
	}
	if _, err := VerifyExecutorGrant(compact, cfg, binding, now); err != nil {
		return GrantObservation{}, false, err
	}
	parts := strings.Split(compact, ".")
	payload, err := decodeGrantPartGrant(parts[1])
	if err != nil {
		return GrantObservation{}, false, err
	}
	var grant executorGrant
	if err = json.Unmarshal(payload, &grant); err != nil {
		return GrantObservation{}, false, err
	}
	scope := cfg.Issuer + "\x00" + cfg.TenantID
	key := digestString(scope + "\x00attempt\x00" + grant.Grant.AttemptID)
	nonce := digestString(scope + "\x00nonce\x00" + grant.Grant.Nonce)
	tuple := grant.Grant
	tuple.AttemptID = ""
	tuple.Nonce = ""
	tupleBytes, err := json.Marshal(tuple)
	if err != nil {
		return GrantObservation{}, false, err
	}
	tupleDigest := digestBytes(tupleBytes)
	var observation GrantObservation
	existingAttempt := false
	if err = j.withState(ctx, func(s *grantJournalState) error {
		if existing, ok := s.Entries[key]; ok {
			if existing.TupleDigest != tupleDigest || existing.NonceDigest != nonce {
				return ErrGrantConflict
			}
			if mapped, ok := s.Nonces[nonce]; ok && mapped != key {
				return ErrGrantConflict
			}
			observation = existing
			existingAttempt = true
			return errJournalExisting
		}
		if _, ok := s.Nonces[nonce]; ok {
			return ErrGrantReplay
		}
		if len(s.Entries) >= grantJournalMaxEntries {
			return ErrGrantJournalFull
		}
		record := GrantObservation{Version: 1, State: GrantObserved, Issuer: cfg.Issuer, Tenant: cfg.TenantID, AttemptDigest: key, NonceDigest: nonce, TupleDigest: tupleDigest, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
		s.Entries[key] = record
		s.Nonces[nonce] = key
		observation = record
		return nil
	}); err != nil {
		return GrantObservation{}, false, err
	}
	return observation, existingAttempt, nil
}

var errJournalExisting = errors.New("journal entry exists")

// Transition performs optimistic evidence-state updates only. Unknown and
// terminal outcomes are immutable; this method cannot trigger an effect.
func (j *grantJournal) Transition(ctx context.Context, attemptDigest string, expectedVersion uint64, next GrantObservationState, now time.Time) (GrantObservation, error) {
	if now.IsZero() {
		return GrantObservation{}, errors.New("grant journal transition time is required")
	}
	var result GrantObservation
	err := j.withState(ctx, func(s *grantJournalState) error {
		r, ok := s.Entries[attemptDigest]
		if !ok {
			return os.ErrNotExist
		}
		if r.Version != expectedVersion {
			return ErrGrantVersion
		}
		if now.Before(r.CreatedAt) || now.Before(r.UpdatedAt) {
			return errors.New("grant journal transition time moved backwards")
		}
		if r.State == GrantUnknown || r.State == GrantAccepted || r.State == GrantRejected {
			return ErrGrantVersion
		}
		valid := (r.State == GrantObserved && (next == GrantPrepared || next == GrantUnknown || next == GrantRejected)) || (r.State == GrantPrepared && (next == GrantUnknown || next == GrantAccepted || next == GrantRejected))
		if !valid {
			return errors.New("invalid grant journal evidence transition")
		}
		r.State = next
		r.Version++
		r.UpdatedAt = now.UTC()
		s.Entries[attemptDigest] = r
		result = r
		return nil
	})
	return result, err
}

func (j *grantJournal) withState(ctx context.Context, mutate func(*grantJournalState) error) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateJournalRoot(j.root); err != nil {
		return err
	}
	// Ordinary operations require a durable enrollment marker before any
	// lock creation or state access. Empty/lost storage never means first use.
	if _, err := os.Lstat(filepath.Join(j.root, "initialized")); err != nil {
		return fmt.Errorf("grant journal is not initialized: %w", err)
	}
	lock, err := j.acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, syscall.Flock(int(lock.Fd()), syscall.LOCK_UN), lock.Close()) }()
	if err = j.verifyLockPath(lock); err != nil {
		return err
	}
	state, err := j.loadState()
	if err != nil {
		return err
	}
	if err = j.validateMarker(lock); err != nil {
		return err
	}

	if err = mutate(&state); err != nil {
		if err == errJournalExisting {
			// Skip replacement for an exact replay, but still surface any
			// deferred lock-release or descriptor-close failure.
			return nil
		}
		return err
	}
	if len(state.Entries) > grantJournalMaxEntries {
		return ErrGrantJournalFull
	}
	raw := marshalGrantJournal(state)
	if len(raw) > grantJournalMaxBytes {
		return ErrGrantJournalFull
	}
	if err = j.verifyLockPath(lock); err != nil {
		return err
	}
	return j.writeFile(filepath.Join(j.root, "state.json"), raw)
}

func (j *grantJournal) loadState() (grantJournalState, error) {
	path := filepath.Join(j.root, "state.json")
	info, err := os.Lstat(path)
	if err != nil {
		return grantJournalState{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) {
		return grantJournalState{}, errors.New("grant journal state file type, mode, or ownership invalid")
	}
	if info.Size() > grantJournalMaxBytes {
		return grantJournalState{}, errors.New("grant journal state exceeds size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return grantJournalState{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, grantJournalMaxBytes+1))
	closeErr := f.Close()
	if err != nil {
		return grantJournalState{}, err
	}
	if closeErr != nil {
		return grantJournalState{}, closeErr
	}
	var s grantJournalState
	if len(raw) > grantJournalMaxBytes || json.Unmarshal(raw, &s) != nil || s.Schema != grantJournalVersion || s.Entries == nil || s.Nonces == nil || len(s.Entries) > grantJournalMaxEntries {
		return grantJournalState{}, errors.New("grant journal state corrupt or unsupported")
	}
	if rejectGrantDuplicates(raw) != nil {
		return grantJournalState{}, errors.New("grant journal state contains duplicate fields")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var exact grantJournalState
	if dec.Decode(&exact) != nil || dec.Decode(new(any)) != io.EOF {
		return grantJournalState{}, errors.New("grant journal state has invalid schema")
	}
	if err = validateGrantJournalIndexes(s); err != nil {
		return grantJournalState{}, err
	}
	return s, nil
}

func validateGrantJournalIndexes(s grantJournalState) error {
	if len(s.Nonces) > grantJournalMaxEntries || len(s.Entries) != len(s.Nonces) {
		return errors.New("grant journal indexes are inconsistent")
	}
	seen := make(map[string]bool, len(s.Entries))
	for key, record := range s.Entries {
		if key != record.AttemptDigest || !validJournalDigest(key) || !validJournalDigest(record.NonceDigest) || !validJournalDigest(record.TupleDigest) || record.Version == 0 || record.Issuer == "" || record.Tenant == "" || record.CreatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
			return errors.New("grant journal record is invalid")
		}
		switch record.State {
		case GrantObserved, GrantPrepared, GrantUnknown, GrantAccepted, GrantRejected:
		default:
			return errors.New("grant journal state value is invalid")
		}
		if (record.State == GrantObserved && record.Version != 1) || (record.State == GrantPrepared && record.Version != 2) || (record.State == GrantAccepted && record.Version != 3) || (record.State == GrantUnknown && (record.Version < 2 || record.Version > 3)) || (record.State == GrantRejected && (record.Version < 2 || record.Version > 3)) {
			return errors.New("grant journal state version is invalid")
		}
		if mapped, ok := s.Nonces[record.NonceDigest]; !ok || mapped != key || seen[record.NonceDigest] {
			return errors.New("grant journal nonce index is inconsistent")
		}
		seen[record.NonceDigest] = true
	}
	for nonce, attempt := range s.Nonces {
		if !validJournalDigest(nonce) || !seen[nonce] || s.Entries[attempt].AttemptDigest != attempt {
			return errors.New("grant journal nonce index is invalid")
		}
	}
	return nil
}

func validJournalDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (j *grantJournal) markerBytes(lock *os.File) []byte {
	st, ok := lockStat(lock)
	if !ok {
		return nil
	}
	return []byte(fmt.Sprintf("grant-journal-v1\n%d:%d\n", st.Dev, st.Ino))
}

func (j *grantJournal) validateMarker(lock *os.File) error {
	path := filepath.Join(j.root, "initialized")
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("grant journal initialization marker missing: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("grant journal initialization marker type, mode, or ownership invalid")
	}
	want := j.markerBytes(lock)
	if int64(len(want)) != info.Size() {
		return errors.New("grant journal initialization marker size invalid")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	openedStat, openedOK := opened.Sys().(*syscall.Stat_t)
	if !openedOK || openedStat.Dev != st.Dev || openedStat.Ino != st.Ino {
		_ = f.Close()
		return errors.New("grant journal initialization marker changed during open")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if string(b) != string(want) {
		return errors.New("grant journal initialization marker corrupt")
	}
	return nil
}

func lockStat(f *os.File) (*syscall.Stat_t, bool) {
	info, err := f.Stat()
	if err != nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}

func (j *grantJournal) verifyLockPath(f *os.File) error {
	fdStat, ok := lockStat(f)
	if !ok {
		return errors.New("grant journal lock descriptor is invalid")
	}
	info, err := os.Lstat(filepath.Join(j.root, "journal.lock"))
	if err != nil {
		return err
	}
	pathStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSymlink != 0 || pathStat.Dev != fdStat.Dev || pathStat.Ino != fdStat.Ino {
		return errors.New("grant journal stable lock path was lost or replaced")
	}
	return nil
}

func (j *grantJournal) acquire(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(j.root, "journal.lock")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if _, markerErr := os.Lstat(filepath.Join(j.root, "initialized")); markerErr == nil {
			return nil, errors.New("grant journal established lock file is missing")
		} else if !os.IsNotExist(markerErr) {
			return nil, markerErr
		}
	} else if err != nil {
		return nil, err
	}
	f, err := j.openFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.Join(errors.New("grant journal lock type, mode, or ownership invalid"), f.Close())
	}
	pathInfo, pathErr := os.Lstat(path)
	if pathErr != nil {
		_ = f.Close()
		return nil, pathErr
	}
	pathStat, pathOK := pathInfo.Sys().(*syscall.Stat_t)
	if !pathOK || pathInfo.Mode()&os.ModeSymlink != 0 || pathStat.Dev != st.Dev || pathStat.Ino != st.Ino {
		_ = f.Close()
		return nil, errors.New("grant journal stable lock path changed during open")
	}
	deadline := time.NewTimer(j.lockTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return nil, ctxErr
			}
			if lockErr := j.verifyLockPath(f); lockErr != nil {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return nil, lockErr
			}
			return f, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return nil, errors.Join(err, f.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), f.Close())
		case <-deadline.C:
			return nil, errors.Join(errors.New("grant journal lock acquisition timed out"), f.Close())
		case <-tick.C:
		}
	}
}

func (j *grantJournal) atomicWrite(path string, raw []byte) (retErr error) {
	if filepath.Dir(path) != j.root {
		return errors.New("grant journal write escaped state root")
	}
	tmp, err := os.CreateTemp(j.root, ".grant-journal-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if e := os.Remove(name); e != nil && !os.IsNotExist(e) {
			retErr = errors.Join(retErr, e)
		}
	}()
	if err = tmp.Chmod(0600); err == nil {
		if j.writeTemp != nil {
			err = j.writeTemp(tmp, raw)
		} else {
			var n int
			n, err = tmp.Write(raw)
			if err == nil && n != len(raw) {
				err = io.ErrShortWrite
			}
		}
	}
	if err == nil {
		if j.syncTemp != nil {
			err = j.syncTemp(tmp)
		} else {
			err = tmp.Sync()
		}
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if j.renameFile != nil {
		err = j.renameFile(name, path)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(j.root)
	if err != nil {
		return err
	}
	var syncErr error
	if j.syncDir != nil {
		syncErr = j.syncDir(j.root)
	} else {
		syncErr = dir.Sync()
	}
	closeErr = dir.Close()
	return errors.Join(syncErr, closeErr)
}

func marshalGrantJournal(v any) []byte { b, _ := json.Marshal(v); return b }
func digestString(s string) string     { return digestBytes([]byte(s)) }
func digestBytes(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func decodeGrantPartGrant(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errInvalidGrant
	}
	return b, nil
}
