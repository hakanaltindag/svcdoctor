package domain

import "errors"

// ErrInvalidValue reports that a domain value is outside its defined range or
// otherwise unusable.
//
// It is a single sentinel rather than one per type because every occurrence
// means the same thing: a programming error produced a value the model cannot
// represent. Callers act on that identically regardless of which value it was.
var ErrInvalidValue = errors.New("invalid domain value")
