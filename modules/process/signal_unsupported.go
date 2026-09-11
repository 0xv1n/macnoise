//go:build !darwin

package process

import (
	"context"
	"fmt"

	"github.com/0xv1n/macnoise/pkg/module"
)

func (p *procSignal) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	return fmt.Errorf("proc_signal is only supported on macOS")
}
