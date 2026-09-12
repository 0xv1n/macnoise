package subprocess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	result, err := Run(context.Background(), os.Args[0], "-test.run=TestRunHelper", "--", "--macnoise-subprocess-helper", "0", "literal ; value")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(result.Output) != "literal ; value" || result.ExitCode != 0 {
		t.Fatalf("result = %+v, want literal output and exit code 0", result)
	}
}

func TestRunReturnsExitErrorAndCode(t *testing.T) {
	result, err := Run(context.Background(), os.Args[0], "-test.run=TestRunHelper", "--", "--macnoise-subprocess-helper", "7", "failed")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run error = %v, want process exit error", err)
	}
	if string(result.Output) != "failed" || result.ExitCode != 7 {
		t.Fatalf("result = %+v, want failed output and exit code 7", result)
	}
}

func TestRunCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Run(ctx, os.Args[0])
	if !errors.Is(err, context.Canceled) || result.ExitCode != -1 {
		t.Fatalf("Run = %+v, %v, want context.Canceled before start", result, err)
	}
}

func TestRunHelper(t *testing.T) {
	index := argumentIndex("--macnoise-subprocess-helper")
	if index < 0 || len(os.Args) < index+3 {
		return
	}
	code, err := strconv.Atoi(os.Args[index+1])
	if err != nil {
		panic(err)
	}
	fmt.Print(os.Args[index+2])
	os.Exit(code)
}

func argumentIndex(want string) int {
	for index, arg := range os.Args {
		if arg == want {
			return index
		}
	}
	return -1
}
