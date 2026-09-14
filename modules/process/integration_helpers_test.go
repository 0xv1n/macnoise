//go:build integration && darwin

package process

import "github.com/0xv1n/macnoise/pkg/module"

func captureProcessEvents(events *[]module.TelemetryEvent) module.EventEmitter {
	return func(event module.TelemetryEvent) error {
		*events = append(*events, event)
		return nil
	}
}
