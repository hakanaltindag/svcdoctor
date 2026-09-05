package diagnosis

import (
	"reflect"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// adviceFieldCount and recommendationFieldCount report the struct arities the
// projection has to be total over.
//
// Reflection rather than a grep: it sees the type the compiler sees, so a field
// added in any file of either package is counted.
func adviceFieldCount() int { return reflect.TypeOf(Advice{}).NumField() }

func recommendationFieldCount() int {
	return reflect.TypeOf(domain.Recommendation{}).NumField()
}
