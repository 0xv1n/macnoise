package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

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
	files []ownedFile
	dirs  []ownedDir
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
		{Name: "stage_dir", Description: "Directory used to stage and encrypt decoy files (only files here are touched)", Type: module.ParamPath, Required: true, Default: defaultEncryptStageDir, Example: "/var/tmp/macnoise_encrypt"},
		{Name: "file_count", Description: "Number of plaintext decoy files to stage before encrypting", Type: module.ParamInteger, Default: 5, Example: 20, Range: &module.IntegerRange{Min: 1, Max: maxFileTargets}},
		{Name: "extension", Description: "Extension appended to encrypted files", Type: module.ParamString, Default: defaultEncryptExtension, Example: ".crypted"},
	}
}

func (f *fileEncrypt) CheckPrereqs(ctx context.Context, params module.Params) error {
	return f.ValidateParams(params)
}

func (f *fileEncrypt) ValidateParams(params module.Params) error {
	return validateEncryptExtension(params.String("extension", defaultEncryptExtension))
}

func (f *fileEncrypt) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "paths", Description: "Concrete encrypted decoy paths", Type: module.ParamPathList}}
}

// stageDecoyFiles writes all plaintext decoys into dir before encryption begins.
// Only these macnoise-created decoys are ever encrypted; the module never reads
// or touches anything the user owns.
func stageDecoyFiles(dir string, count int) ([]string, error) {
	paths := make([]string, 0, count)
	owned := make([]ownedFile, 0, count)
	for i := range count {
		extension, err := randomDecoyExtension()
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, fmt.Sprintf("document_%d%s", i, extension))
		content := fmt.Sprintf("macnoise decoy document %d - simulated victim data\n", i)
		file, err := createOwnedFile(p, []byte(content), 0o644)
		if err != nil {
			_ = removeOwnedFiles(owned)
			return nil, err
		}
		owned = append(owned, file)
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
	if _, err := createOwnedFile(encPath, ciphertext, 0o644); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return encPath, err
	}
	return encPath, nil
}

func (f *fileEncrypt) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	stageDir := params.String("stage_dir", defaultEncryptStageDir)
	extension := params.String("extension", defaultEncryptExtension)
	count := params.Int("file_count", defaultEncryptCount)
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	info := f.Info()

	// One key per run is generated fresh. The nonce is stored with each
	// ciphertext, matching the AES-GCM file layout used by the round-trip test.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	createdDirs, err := ensureDirs(stageDir, 0o700)
	f.dirs = append(f.dirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	paths, err := stageDecoyFiles(stageDir, count)
	if err != nil {
		return fmt.Errorf("stage decoy files: %w", err)
	}
	for _, path := range paths {
		owned, captureErr := captureOwnedFile(path)
		if captureErr != nil {
			return captureErr
		}
		f.files = append(f.files, owned)
	}

	var resultErr error
	var encryptedPaths []string
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ev := output.NewEvent(info, "file_encrypt", module.OutcomeError, module.File(p+extension), fmt.Sprintf("encrypting %s", p))
		encPath, encErr := encryptFile(p, extension, key)
		if encErr != nil {
			if encPath != "" {
				if owned, captureErr := captureOwnedFile(encPath); captureErr == nil {
					f.files = append(f.files, owned)
				}
			}
			ev = output.WithError(ev, encErr)
			resultErr = errors.Join(resultErr, encErr, emit(ev))
			continue
		}
		owned, captureErr := captureOwnedFile(encPath)
		if captureErr != nil {
			return errors.Join(resultErr, captureErr)
		}
		f.files = append(f.files, owned)
		encryptedPaths = append(encryptedPaths, encPath)
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("encrypted %s -> %s", p, encPath)
		ev = output.WithDetails(ev, map[string]any{
			"original":  p,
			"encrypted": encPath,
			"cipher":    "AES-256-GCM",
		})
		if err := emit(ev); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	return errors.Join(resultErr, module.PublishOutput(ctx, "paths", encryptedPaths))
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
	err := errors.Join(removeOwnedFiles(f.files), removeOwnedDirs(f.dirs))
	f.files = nil
	f.dirs = nil
	return err
}

func validateEncryptExtension(extension string) error {
	if extension == "" || !strings.HasPrefix(extension, ".") || filepath.Base(extension) != extension {
		return fmt.Errorf("extension must be a file-name suffix beginning with a dot: %q", extension)
	}
	return nil
}

func init() {
	module.Register(func() module.Generator { return &fileEncrypt{} })
}
