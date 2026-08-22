package cli

import (
	"errors"
	"fmt"
)

// ErrUsage marks a failure caused by how svcdoctor was invoked.
//
// # Why the distinction is structural rather than a judgement call
//
// docs/SCOPE.md gives usage errors exit code 2 and internal failures exit code
// 3, and the two mean opposite things to whoever is reading: 2 says *you asked
// for something svcdoctor cannot act on*, 3 says *svcdoctor broke*. A CI job
// that retries on 3 and stops on 2 is behaving correctly; one that cannot tell
// them apart is not.
//
// So the classification is carried by the error itself and never inferred at the
// point the exit code is chosen. Everything the argument parser rejects wraps
// this; anything else that escapes a valid invocation is, by definition, a
// failure svcdoctor did not anticipate, and it becomes a 3.
//
// internal/app.ErrInvalidInput is treated the same way. It means the composition
// root was handed something it cannot run with, which is the same class of fact
// one layer down.
var ErrUsage = errors.New("invalid invocation")

// usagef builds a usage error with a message the operator can act on.
//
// The wrapping is what ExitCode reads. The message is what the operator reads,
// so it names the flag and the value rather than the internal condition — and it
// never carries file contents, only paths (ADR 0049).
func usagef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, args...))
}
