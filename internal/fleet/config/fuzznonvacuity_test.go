package config_test

import (
	"errors"
	"testing"
)

// TestTheInterpolationCheckIsNotVacuous proves assertNoInterpolatedValue would
// actually catch a bypassed sanitizer, by handing it the raw library text.
func TestTheInterpolationCheckIsNotVacuous(t *testing.T) {
	raw := errors.New("line 6: cannot unmarshal !!str `hunter2` into config.credentialRef")
	fake := &testing.T{}
	assertNoInterpolatedValue(fake, raw)
	if !fake.Failed() {
		t.Error("assertNoInterpolatedValue accepted an unsanitized library error")
	}

	safe := errors.New("line 6: cannot unmarshal !!str `<value redacted>` into int")
	clean := &testing.T{}
	assertNoInterpolatedValue(clean, safe)
	if clean.Failed() {
		t.Error("assertNoInterpolatedValue rejected correctly sanitized output")
	}
}
