package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const maxFileTargets = 100

var errDiscoveryLimit = errors.New("file discovery limit reached")

type fileFind struct{}

func (f *fileFind) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_find",
		EventTypes:  []string{"file_discover"},
		Description: "Finds a bounded set of regular files beneath explicit roots",
		Category:    module.CategoryFile,
		Tags:        []string{"file", "discovery", "collection"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1083", Name: "File and Directory Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileFind) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "roots", Description: "Literal roots to search without following symbolic links", Type: module.ParamPathList, Required: true, Example: []string{"/Users/dev/Documents"}},
		{Name: "names", Description: "Exact file names to include; empty includes every name", Type: module.ParamStringList, Default: []string{}, Example: []string{"Login Data", "credentials"}},
		{Name: "extensions", Description: "File extensions to include; empty includes every extension", Type: module.ParamStringList, Default: []string{}, Example: []string{".txt", ".docx"}},
		{Name: "max_depth", Description: "Maximum directory depth below each root", Type: module.ParamInteger, Default: 3, Example: 5, Range: &module.IntegerRange{Min: 0, Max: 16}},
		{Name: "max_results", Description: "Maximum number of concrete paths returned", Type: module.ParamInteger, Default: maxFileTargets, Example: 25, Range: &module.IntegerRange{Min: 1, Max: maxFileTargets}},
		{Name: "max_bytes", Description: "Maximum file size in bytes; zero disables the size filter", Type: module.ParamInteger, Default: 0, Example: 51200, Range: &module.IntegerRange{Min: 0}},
	}
}

func (f *fileFind) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "paths", Description: "Bounded concrete paths found beneath the declared roots", Type: module.ParamPathList}}
}

func (f *fileFind) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (f *fileFind) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := f.Info()
	names := lowerSet(params.Strings("names", nil))
	extensions := lowerSet(params.Strings("extensions", nil))
	maxDepth := params.Int("max_depth", 3)
	maxResults := params.Int("max_results", maxFileTargets)
	maxBytes := int64(params.Int("max_bytes", 0))
	paths := make([]string, 0, maxResults)
	seen := make(map[string]bool)

	for _, declaredRoot := range params.Paths("roots", []string{"/tmp/macnoise_test"}) {
		if err := ctx.Err(); err != nil {
			return err
		}
		root, err := filepath.Abs(declaredRoot)
		if err != nil {
			return err
		}
		root = filepath.Clean(root)
		rootInfo, err := os.Lstat(root)
		if os.IsNotExist(err) {
			ev := output.NewEvent(info, "file_discover", module.OutcomeIndeterminate, module.File(root), fmt.Sprintf("discovery root not present: %s", root))
			ev = output.WithDetails(ev, map[string]any{"root": root, "exists": false})
			if err := emit(ev); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if rootInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("discovery root must not be a symbolic link: %s", root)
		}

		before := len(paths)
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				outcome := module.OutcomeError
				if os.IsPermission(walkErr) {
					outcome = module.OutcomeDenied
				}
				ev := output.NewEvent(info, "file_discover", outcome, module.File(path), fmt.Sprintf("cannot inspect %s", path))
				ev = output.WithError(ev, walkErr)
				if err := emit(ev); err != nil {
					return err
				}
				if outcome == module.OutcomeDenied {
					if entry != nil && entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("discovered path escaped root %s: %s", root, path)
			}
			depth := 0
			if rel != "." {
				depth = strings.Count(rel, string(filepath.Separator)) + 1
			}
			if entry.IsDir() {
				if depth > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if depth > maxDepth || !entry.Type().IsRegular() || !matchesTarget(entry.Name(), names, extensions) {
				return nil
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}
			if maxBytes > 0 && entryInfo.Size() > maxBytes {
				return nil
			}
			concrete := filepath.Clean(path)
			if seen[concrete] {
				return nil
			}
			seen[concrete] = true
			paths = append(paths, concrete)
			ev := output.NewEvent(info, "file_discover", module.OutcomeExecuted, module.File(concrete), fmt.Sprintf("discovered %s", concrete))
			ev = output.WithDetails(ev, map[string]any{"path": concrete, "root": root, "size": entryInfo.Size()})
			if err := emit(ev); err != nil {
				return err
			}
			if len(paths) >= maxResults {
				return errDiscoveryLimit
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, errDiscoveryLimit) {
			return walkErr
		}
		if len(paths) == before {
			ev := output.NewEvent(info, "file_discover", module.OutcomeIndeterminate, module.File(root), fmt.Sprintf("no matching files beneath %s", root))
			ev = output.WithDetails(ev, map[string]any{"root": root, "matches": 0})
			if err := emit(ev); err != nil {
				return err
			}
		}
		if len(paths) >= maxResults {
			break
		}
	}
	return module.PublishOutput(ctx, "paths", paths)
}

func (f *fileFind) DryRun(params module.Params) []string {
	return []string{fmt.Sprintf("find at most %d regular files, depth %d, beneath literal roots: %s",
		params.Int("max_results", maxFileTargets), params.Int("max_depth", 3), strings.Join(params.Paths("roots", nil), ", "))}
}

func (f *fileFind) Cleanup(ctx context.Context) error { return nil }

func lowerSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.ToLower(value)] = true
	}
	return set
}

func matchesTarget(name string, names, extensions map[string]bool) bool {
	if len(names) == 0 && len(extensions) == 0 {
		return true
	}
	lower := strings.ToLower(name)
	return names[lower] || extensions[strings.ToLower(filepath.Ext(name))]
}

func init() {
	module.Register(func() module.Generator { return &fileFind{} })
}
