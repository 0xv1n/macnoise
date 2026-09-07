package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	defaultEncryptStageDir  = "/tmp/macnoise_encrypt"
	defaultEncryptExtension = ".locked"
	defaultEncryptCount     = 5
	ransomNoteName          = "RECOVER_YOUR_FILES.txt"
)

type fileEncrypt struct {
	stageDir string
}

func (f *fileEncrypt) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_encrypt",
		EventTypes:  []string{"file_encrypt", "ransom_note_drop"},
		Description: "Encrypts staged decoy files in place with AES-GCM and drops a ransom note to generate ransomware impact telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"ransomware", "encryption", "impact", "aes"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1486", Name: "Data Encrypted for Impact"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileEncrypt) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "stage_dir", Description: "Directory of decoy files to encrypt (only files here are touched)", Required: false, DefaultValue: defaultEncryptStageDir, Example: "/var/tmp/macnoise_encrypt"},
		{Name: "file_count", Description: "Number of decoy files to create and encrypt", Required: false, DefaultValue: "5", Example: "20"},
		{Name: "extension", Description: "Extension appended to encrypted files", Required: false, DefaultValue: defaultEncryptExtension, Example: ".crypted"},
	}
}

func (f *fileEncrypt) CheckPrereqs() error { return nil }

// stageDecoyFiles writes count throwaway files into dir and returns their paths.
// Only these macnoise-created decoys are ever encrypted; the module never reads
// or touches anything the user owns.
func stageDecoyFiles(dir string, count int) ([]string, error) {
	paths := make([]string, 0, count)
	for i := range count {
		p := filepath.Join(dir, fmt.Sprintf("decoy_%d.dat", i))
		content := fmt.Sprintf("macnoise decoy document %d - simulated victim data\n", i)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// encryptFile AES-GCM encrypts the file at path, writes the ciphertext to
// path+extension, and removes the plaintext original. It returns the encrypted
// path. The nonce is prepended to the ciphertext so the operation is
// reversible with the key, which keeps this a faithful simulation rather than
// irreversible destruction.
func encryptFile(path, extension string, key []byte) (string, error) {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encPath := path + extension
	if err := os.WriteFile(encPath, ciphertext, 0o644); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return encPath, nil
}

func (f *fileEncrypt) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	runID := module.RunIDFromContext(ctx)
	stageDir := module.TagPath(params.Get("stage_dir", defaultEncryptStageDir), runID)
	extension := params.Get("extension", defaultEncryptExtension)
	count := defaultEncryptCount
	fmt.Sscanf(params.Get("file_count", "5"), "%d", &count) //nolint:errcheck
	if count < 1 {
		count = 1
	}
	info := f.Info()

	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	f.stageDir = stageDir

	paths, err := stageDecoyFiles(stageDir, count)
	if err != nil {
		return fmt.Errorf("stage decoy files: %w", err)
	}

	// One key per run, generated fresh. It is recorded in the ransom-note event
	// details so the encryption is transparently reversible, not destructive.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	encrypted := 0
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ev := output.NewEvent(info, "file_encrypt", false, fmt.Sprintf("encrypting %s", p))
		encPath, encErr := encryptFile(p, extension, key)
		if encErr != nil {
			ev = output.WithError(ev, encErr)
			emit(ev)
			continue
		}
		encrypted++
		ev.Success = true
		ev.Message = fmt.Sprintf("encrypted %s -> %s", p, encPath)
		ev = output.WithDetails(ev, map[string]any{
			"original":  p,
			"encrypted": encPath,
			"cipher":    "AES-256-GCM",
		})
		emit(ev)
	}

	notePath := filepath.Join(stageDir, ransomNoteName)
	note := fmt.Sprintf("Your files have been encrypted.\nThis is a MacNoise simulation. Recovery key (hex): %s\n", hex.EncodeToString(key))
	noteEv := output.NewEvent(info, "ransom_note_drop", false, fmt.Sprintf("dropping ransom note at %s", notePath))
	if err := os.WriteFile(notePath, []byte(note), 0o644); err != nil {
		noteEv = output.WithError(noteEv, err)
		emit(noteEv)
		return nil
	}
	noteEv.Success = true
	noteEv.Message = fmt.Sprintf("ransom note written to %s", notePath)
	noteEv = output.WithDetails(noteEv, map[string]any{
		"path":             notePath,
		"files_encrypted":  encrypted,
		"recovery_key_hex": hex.EncodeToString(key),
	})
	emit(noteEv)
	return nil
}

func (f *fileEncrypt) DryRun(params module.Params) []string {
	stageDir := params.Get("stage_dir", defaultEncryptStageDir)
	extension := params.Get("extension", defaultEncryptExtension)
	count := params.Get("file_count", "5")
	return []string{
		fmt.Sprintf("create %s decoy files in %s", count, stageDir),
		fmt.Sprintf("AES-256-GCM encrypt each in place, appending %q and removing the original (T1486)", extension),
		fmt.Sprintf("drop ransom note %s in %s", ransomNoteName, stageDir),
	}
}

func (f *fileEncrypt) Cleanup() error {
	if f.stageDir == "" {
		return nil
	}
	return os.RemoveAll(f.stageDir)
}

func init() {
	module.Register(&fileEncrypt{})
}
