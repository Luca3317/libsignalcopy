package tests

import (
	"github.com/Luca3317/libsignalcopy/serialize"
)

// newSerializer will return a JSON serializer for testing.
func newSerializer() *serialize.Serializer {
	serializer := serialize.NewJSONSerializer()

	return serializer
}
