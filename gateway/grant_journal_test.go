package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func journalFixture(t *testing.T, root string) (*grantJournal, string, GrantConsumerConfig, GrantExecutionBinding, time.Time) {
	t.Helper()
	token, cfg, binding, now := grantTestVector(t)
	j, err := NewGrantJournal(GrantJournalConfig{StateRoot: root, LockTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return j, token, cfg, binding, now
}

func journalTempDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "eaap-grant-journal-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func tokenWithNonce(t *testing.T, token, nonce string) string {
	t.Helper()
	p := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		t.Fatal(err)
	}
	var m executorGrant
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Claims.JTI = nonce
	m.Grant.Nonce = nonce
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return signGrantPayload(ed25519PrivateForTest(t), string(raw), `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`)
}

func tokenWithAttempt(t *testing.T, token, attempt string) string {
	t.Helper()
	p := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		t.Fatal(err)
	}
	var m executorGrant
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Grant.AttemptID = attempt
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return signGrantPayload(ed25519PrivateForTest(t), string(raw), `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`)
}

func tokenWithDestinationHash(t *testing.T, token, hash string) string {
	t.Helper()
	p := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		t.Fatal(err)
	}
	var m executorGrant
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Grant.DestinationHash = hash
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return signGrantPayload(ed25519PrivateForTest(t), string(raw), `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`)
}

func ed25519PrivateForTest(t *testing.T) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(grantTestSeed[:])
	return key
}

func TestGrantJournalReplayConflictAndReopen(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	first, existing, err := j.Observe(context.Background(), token, cfg, binding, now)
	if err != nil || existing {
		t.Fatalf("first observation: %v existing=%v", err, existing)
	}
	j2, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	repeat, existing, err := j2.Observe(context.Background(), token, cfg, binding, now)
	if err != nil || !existing || repeat.AttemptDigest != first.AttemptDigest {
		t.Fatalf("repeat: %v existing=%v", err, existing)
	}
	if _, _, err = j.Observe(context.Background(), tokenWithNonce(t, token, "nonce-refresh"), cfg, binding, now); !errors.Is(err, ErrGrantConflict) {
		t.Fatalf("refreshed nonce same attempt = %v", err)
	}
	changedBinding := binding
	changedBinding.DestinationHash = strings.Repeat("c", 64)
	if _, _, err = j.Observe(context.Background(), tokenWithDestinationHash(t, token, changedBinding.DestinationHash), cfg, changedBinding, now); !errors.Is(err, ErrGrantConflict) {
		t.Fatalf("changed immutable tuple same attempt = %v", err)
	}
	other := tokenWithAttempt(t, token, "attempt-other")
	if _, _, err = j.Observe(context.Background(), other, cfg, binding, now); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("same nonce/different attempt = %v", err)
	}
	if _, err = j.Transition(context.Background(), first.AttemptDigest, 1, GrantUnknown, now); err != nil {
		t.Fatal(err)
	}
	j3, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	got, existing, err := j3.Observe(context.Background(), token, cfg, binding, now)
	if err != nil || !existing || got.State != GrantUnknown {
		t.Fatalf("unknown not retained: %+v %v", got, err)
	}
	if _, err = j3.Transition(context.Background(), first.AttemptDigest, 2, GrantAccepted, now); !errors.Is(err, ErrGrantVersion) {
		t.Fatalf("unknown outcome changed: %v", err)
	}
}

func TestGrantJournalConcurrentOpenReplay(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, repeats := 0, 0
	errs := []error{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, e := NewGrantJournal(GrantJournalConfig{StateRoot: root})
			if e == nil {
				var existed bool
				_, existed, e = other.Observe(context.Background(), token, cfg, binding, now)
				if e == nil {
					mu.Lock()
					if existed {
						repeats++
					} else {
						successes++
					}
					mu.Unlock()
				}
			}
			if e != nil {
				mu.Lock()
				errs = append(errs, e)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 || repeats != n-1 || len(errs) > 0 {
		t.Fatalf("success=%d repeats=%d errs=%v", successes, repeats, errs)
	}
	_ = j
}

func TestGrantJournalUnsafePathsAndEstablishedStateFailClosed(t *testing.T) {
	parent := journalTempDir(t)
	link := filepath.Join(parent, "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrantJournal(GrantJournalConfig{StateRoot: filepath.Join(link, "journal")}); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	root := filepath.Join(parent, "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err == nil {
		t.Fatal("missing established state silently reset")
	}
	root2 := filepath.Join(parent, "mode")
	if err := os.Mkdir(root2, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrantJournal(GrantJournalConfig{StateRoot: root2}); err == nil {
		t.Fatal("permissive root accepted")
	}
}

func TestGrantJournalCorruptIndexesAndMarkerLossFailClosed(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state grantJournalState
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Nonces = map[string]string{}
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Observe(context.Background(), token, cfg, binding, now); err == nil {
		t.Fatal("inconsistent nonce index accepted")
	}
	if err = os.WriteFile(statePath, marshalGrantJournal(grantJournalState{Schema: grantJournalVersion, Entries: map[string]GrantObservation{}, Nonces: map[string]string{}}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(root, "initialized")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Observe(context.Background(), token, cfg, binding, now); err == nil {
		t.Fatal("lost initialization marker repaired silently")
	}
}

func TestGrantJournalRejectsLostOrReplacedStableLock(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "replaced"}[replace], func(t *testing.T) {
			root := filepath.Join(journalTempDir(t), "journal")
			j, token, cfg, binding, now := journalFixture(t, root)
			if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
				t.Fatal(err)
			}
			lockPath := filepath.Join(root, "journal.lock")
			if replace {
				if err := os.Rename(lockPath, filepath.Join(root, "old-lock")); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err == nil {
				t.Fatal("lost or replaced stable lock accepted")
			}
		})
	}
}

func TestGrantJournalRejectsUnsafePersistedFileModes(t *testing.T) {
	for _, file := range []string{"state.json", "journal.lock"} {
		t.Run(file, func(t *testing.T) {
			root := filepath.Join(journalTempDir(t), "journal")
			j, token, cfg, binding, now := journalFixture(t, root)
			if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, file)
			if err := os.Chmod(path, 0640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err == nil {
				t.Fatal("permissive persisted file mode accepted")
			}
		})
	}
}

func TestGrantJournalCanceledContextDoesNotInitialize(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := j.Observe(ctx, token, cfg, binding, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observe = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("canceled context initialized state: %v", err)
	}
}

func TestGrantJournalWriteFailurePreservesPriorState(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename"} {
		t.Run(stage, func(t *testing.T) {
			root := filepath.Join(journalTempDir(t), "journal")
			j, token, cfg, binding, now := journalFixture(t, root)
			observation, _, err := j.Observe(context.Background(), token, cfg, binding, now)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected atomic replacement failure")
			switch stage {
			case "write":
				j.writeTemp = func(*os.File, []byte) error { return injected }
			case "file-sync":
				j.syncTemp = func(*os.File) error { return injected }
			case "rename":
				j.renameFile = func(string, string) error { return injected }
			}
			if _, err = j.Transition(context.Background(), observation.AttemptDigest, 1, GrantPrepared, now); !errors.Is(err, injected) {
				t.Fatalf("injected replacement failure = %v", err)
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("pre-rename failure changed prior state")
			}
		})
	}
	t.Run("directory-sync-after-rename", func(t *testing.T) {
		root := filepath.Join(journalTempDir(t), "journal")
		j, token, cfg, binding, now := journalFixture(t, root)
		observation, _, err := j.Observe(context.Background(), token, cfg, binding, now)
		if err != nil {
			t.Fatal(err)
		}
		j.syncDir = func(string) error { return errors.New("injected directory sync failure") }
		if _, err = j.Transition(context.Background(), observation.AttemptDigest, 1, GrantPrepared, now); err == nil {
			t.Fatal("directory sync failure ignored")
		}
		j.syncDir = nil
		j2, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
		if err != nil {
			t.Fatal(err)
		}
		got, existing, err := j2.Observe(context.Background(), token, cfg, binding, now)
		if err != nil || !existing || got.State != GrantPrepared {
			t.Fatalf("renamed complete state unavailable: %+v existing=%v err=%v", got, existing, err)
		}
	})
}

func TestGrantJournalVersionedLifecycle(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	observation, _, err := j.Observe(context.Background(), token, cfg, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Transition(context.Background(), observation.AttemptDigest, 9, GrantPrepared, now); !errors.Is(err, ErrGrantVersion) {
		t.Fatalf("stale version = %v", err)
	}
	prepared, err := j.Transition(context.Background(), observation.AttemptDigest, 1, GrantPrepared, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := j.Transition(context.Background(), observation.AttemptDigest, prepared.Version, GrantAccepted, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Transition(context.Background(), observation.AttemptDigest, accepted.Version, GrantRejected, now.Add(3*time.Second)); !errors.Is(err, ErrGrantVersion) {
		t.Fatalf("terminal state changed = %v", err)
	}
	if _, _, err = j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
}

func TestGrantJournalRejectsInvalidTransitionTimeWithoutCorruptingState(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	observation, _, err := j.Observe(context.Background(), token, cfg, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, badTime := range map[string]time.Time{"zero": {}, "backdated": now.Add(-time.Second)} {
		t.Run(name, func(t *testing.T) {
			if _, err := j.Transition(context.Background(), observation.AttemptDigest, 1, GrantPrepared, badTime); err == nil {
				t.Fatal("invalid transition time accepted")
			}
		})
	}
	got, existing, err := j.Observe(context.Background(), token, cfg, binding, now)
	if err != nil || !existing || got.State != GrantObserved {
		t.Fatalf("invalid time poisoned state: %+v %v", got, err)
	}
}

func TestGrantJournalLockWaitIsBounded(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(root, "journal.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	j.lockTimeout = 30 * time.Millisecond
	start := time.Now()
	_, _, err = j.Observe(context.Background(), token, cfg, binding, now)
	elapsed := time.Since(start)
	unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	closeErr := lock.Close()
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("contended lock result: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("lock timeout was not bounded: %v", elapsed)
	}
	if unlockErr != nil || closeErr != nil {
		t.Fatalf("release test lock: %v %v", unlockErr, closeErr)
	}
}

func TestGrantJournalSubprocessCrashPersistence(t *testing.T) {
	if os.Getenv("EAAP_JOURNAL_CHILD") == "1" {
		root := os.Getenv("EAAP_JOURNAL_ROOT")
		j, token, cfg, binding, now := journalFixture(t, root)
		_, existing, err := j.Observe(context.Background(), token, cfg, binding, now)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(os.Getenv("EAAP_JOURNAL_RESULT"), []byte(map[bool]string{true: "existing", false: "new"}[existing]), 0600); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	root := filepath.Join(journalTempDir(t), "journal")
	token, _, _, _ := grantTestVector(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	results := make([]string, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result := filepath.Join(journalTempDir(t), "result")
			cmd := exec.Command(os.Args[0], "-test.run=^TestGrantJournalSubprocessCrashPersistence$")
			cmd.Env = append(os.Environ(), "EAAP_JOURNAL_CHILD=1", "EAAP_JOURNAL_ROOT="+root, "EAAP_JOURNAL_RESULT="+result, "EAAP_JOURNAL_TOKEN="+token)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("child: %w %s", err, out)
				return
			}
			b, err := os.ReadFile(result)
			if err != nil {
				errs <- err
				return
			}
			results[i] = string(b)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	newCount, existingCount := 0, 0
	for _, r := range results {
		switch r {
		case "new":
			newCount++
		case "existing":
			existingCount++
		}
	}
	if newCount != 1 || existingCount != 1 {
		t.Fatalf("subprocess race results: %v", results)
	}
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, existing, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil || !existing {
		t.Fatalf("child observation absent after process exit: existing=%v err=%v", existing, err)
	}
}
