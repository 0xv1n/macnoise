package file

import (
	"context"

	"github.com/0xv1n/macnoise/pkg/module"
)

func outputContext() (context.Context, module.Params) {
	outputs := module.Params{}
	ctx := module.ContextWithOutputSink(context.Background(), func(name string, value any) error {
		outputs[name] = value
		return nil
	})
	return ctx, outputs
}
