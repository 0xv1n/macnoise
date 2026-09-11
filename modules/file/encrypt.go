package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	defaultEncryptStageDir  = "/tmp/macnoise_encrypt"
	defaultEncryptExtension = ".locked"
	defaultEncryptCount     = 5
)

var decoyExtensions = []string{
	".docx", ".xlsx", ".pdf", ".jpg", ".png", ".txt", ".zip",
}

type fileEncrypt struct {
	stageDir string
}

func (f *fileEncrypt) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_encrypt",
		EventTypes:  []string{"file_encrypt"},
		Description: "Stages plaintext decoy files and encrypts them in place with AES-GCM to generate ransomware impact telemetry",
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
		{Name: "stage_dir", Description: "Directory used to stage and encrypt decoy files (only files here are touched)", Type: module.ParamPath, Default: defaultEncryptStageDir, Example: "/var/tmp/macnoise_encrypt"},
		{Name: "file_count", Description: "Number of plaintext decoy files to stage before encrypting", Type: module.ParamInteger, Default: 5, Example: 20, Range: &module.IntegerRange{Min: 1}},
		{Name: "extension", Description: "Extension appended to encrypted files", Type: module.ParamString, Default: defaultEncryptExtension, Example: ".crypted"},
	}
}

func (f *fileEncrypt) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

// stageDecoyFiles writes all plaintext decoys into dir before encryption begins.
// Only these macnoise-created decoys are ever encrypted; the module never reads
// or touches anything the user owns.
func stageDecoyFiles(dir string, count int) ([]string, error) {
	paths := make([]string, 0, count)
	for i := range count {
		extension, err := randomDecoyExtension()
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, fmt.Sprintf("document_%d%s", i, extension))
		content := fmt.Sprintf("macnoise decoy document %d - simulated victim data\n", i)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func randomDecoyExtension() (string, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(decoyExtensions))))
	if err != nil {
		return "", err
	}
	return decoyExtensions[index.Int64()], nil
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
	stageDir := module.TagPath(params.String("stage_dir", defaultEncryptStageDir), runID)
	extension := params.String("extension", defaultEncryptExtension)
	count := params.Int("file_count", defaultEncryptCount)
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

	// One key per run is generated fresh. The nonce is stored with each
	// ciphertext, matching the AES-GCM file layout used by the round-trip test.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

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
		ev.Success = true
		ev.Message = fmt.Sprintf("encrypted %s -> %s", p, encPath)
		ev = output.WithDetails(ev, map[string]any{
			"original":  p,
			"encrypted": encPath,
			"cipher":    "AES-256-GCM",
		})
		emit(ev)
	}
	return nil
}

func (f *fileEncrypt) DryRun(params module.Params) []string {
	stageDir := params.String("stage_dir", defaultEncryptStageDir)
	extension := params.String("extension", defaultEncryptExtension)
	count := params.Int("file_count", defaultEncryptCount)
	return []string{
		fmt.Sprintf("stage %d plaintext decoy files with randomized extensions in %s", count, stageDir),
		fmt.Sprintf("AES-256-GCM encrypt each in place, appending %q and removing the original (T1486)", extension),
	}
}

func (f *fileEncrypt) Cleanup(ctx context.Context) error {
	if f.stageDir == "" {
		return nil
	}
	return os.RemoveAll(f.stageDir)
}

func init() {
	module.Register(func() module.Generator { return &fileEncrypt{} })
}
