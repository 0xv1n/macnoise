package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// decrypt reverses encryptFile, proving the operation is a faithful (reversible)
// encryption rather than corruption.
func decrypt(t *testing.T, ciphertext, key []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		t.Fatalf("ciphertext too short: %d < nonce %d", len(ciphertext), ns)
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return pt
}

func TestEncryptFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	plaintext := []byte("top secret victim data")
	if err := os.WriteFile(path, plaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	encPath, err := encryptFile(path, ".locked", key)
	if err != nil {
		t.Fatalf("encryptFile: %v", err)
	}

	// The original plaintext must be gone and the encrypted file must exist.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("original plaintext should be removed, stat err = %v", err)
	}
	if encPath != path+".locked" {
		t.Errorf("encrypted path = %q, want %q", encPath, path+".locked")
	}

	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	// It must not be stored in the clear.
	if strings.Contains(string(ciphertext), "victim data") {
		t.Error("ciphertext still contains plaintext")
	}
	// And it must decrypt back to exactly the original with the run's key.
	if got := decrypt(t, ciphertext, key); string(got) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestGenerate_EncryptsAllAndDropsNote(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "enc")

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	f := &fileEncrypt{}
	if err := f.Generate(context.Background(), module.Params{"stage_dir": stage, "file_count": "4"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var encEvents, noteEvents int
	for _, ev := range events {
		switch ev.EventType {
		case "file_encrypt":
			encEvents++
			if !ev.Success {
				t.Errorf("file_encrypt failed: %s", ev.Message)
			}
		case "ransom_note_drop":
			noteEvents++
			if ev.Details["files_encrypted"] != 4 {
				t.Errorf("files_encrypted = %v, want 4", ev.Details["files_encrypted"])
			}
		}
	}
	if encEvents != 4 {
		t.Errorf("emitted %d file_encrypt events, want 4", encEvents)
	}
	if noteEvents != 1 {
		t.Errorf("emitted %d ransom_note_drop events, want 1", noteEvents)
	}

	// No plaintext decoys should remain; only .locked files and the note.
	entries, err := os.ReadDir(stage)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".dat") {
			t.Errorf("plaintext decoy %s was left behind", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(stage, ransomNoteName)); err != nil {
		t.Errorf("ransom note not written: %v", err)
	}
}

func TestEncryptDryRun(t *testing.T) {
	steps := (&fileEncrypt{}).DryRun(module.Params{"file_count": "9", "extension": ".crypted"})
	if len(steps) != 3 {
		t.Fatalf("dry run = %v, want 3 steps", steps)
	}
	joined := strings.Join(steps, "\n")
	for _, want := range []string{"9 decoy files", ".crypted", "T1486", ransomNoteName} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run missing %q:\n%s", want, joined)
		}
	}
}

func TestEncryptCleanup_RemovesStageDir(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "enc")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fileEncrypt{stageDir: stage}
	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("stage dir should be removed, stat err = %v", err)
	}
}
