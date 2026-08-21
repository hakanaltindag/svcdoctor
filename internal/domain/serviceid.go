package domain

import "fmt"

// ServiceID names the service a run inspected, for example "kafka" or
// "postgres".
//
// It is a validated string rather than an enumeration. A closed set would have
// to name every present and future service in the core, so adding a service
// would mean editing shared code. That is the same coupling docs/FINDINGS.md
// rejects for finding codes, in a different shape.
//
// The format is checked; the set of names is not. Validation must never hold a
// list of known services.
type ServiceID string

// NewServiceID validates a service name.
//
// The grammar is a single lowercase segment:
//
//	1*( lowercase letter / digit / "_" )
//
// Case is fixed so that "Kafka" and "kafka" cannot both appear and split what
// should be one service in every report and every dashboard query.
func NewServiceID(s string) (ServiceID, error) {
	if s == "" {
		return "", fmt.Errorf("%w: service id must not be empty", ErrInvalidValue)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return "", fmt.Errorf(
				"%w: service id %q may contain only lowercase letters, digits and underscore",
				ErrInvalidValue, s)
		}
	}
	return ServiceID(s), nil
}

// Valid reports whether id satisfies the grammar documented on NewServiceID.
func (id ServiceID) Valid() bool {
	_, err := NewServiceID(string(id))
	return err == nil
}

// String returns the service name.
func (id ServiceID) String() string { return string(id) }
