package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGrantJournalReopenCannotResetLostDirectory(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	// Preserve the original store while simulating its configured path disappearing.
	if err := os.Rename(root, root+"-preserved"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
	if err == nil {
		_, existing, observeErr := reopened.Observe(context.Background(), token, cfg, binding, now)
		if observeErr == nil && !existing {
			t.Fatal("lost established directory silently recreated a fresh observation")
		}
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("ordinary reopen recreated missing state root: %v", err)
	}
}

func TestGrantJournalReopenCannotInitializeEmptyDirectory(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	token, cfg, binding, now := grantTestVector(t)
	j, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
	if err == nil {
		if _, _, err = j.Observe(context.Background(), token, cfg, binding, now); err == nil {
			t.Fatal("ordinary reopen implicitly initialized empty directory")
		}
	}
}

func TestGrantJournalExplicitInitializationCannotReplaceExistingStore(t *testing.T) {
	root := filepath.Join(journalTempDir(t), "journal")
	j, token, cfg, binding, now := journalFixture(t, root)
	if _, _, err := j.Observe(context.Background(), token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeGrantJournal(GrantJournalConfig{StateRoot: root}); err == nil {
		t.Fatal("explicit initialization replaced existing root")
	}
	reopened, err := NewGrantJournal(GrantJournalConfig{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, existing, err := reopened.Observe(context.Background(), token, cfg, binding, now); err != nil || !existing {
		t.Fatalf("prior history changed: existing=%v err=%v", existing, err)
	}
}
