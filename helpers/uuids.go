package helpers

import (
	"regexp"
)

const _uuidRegex = "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
var /* const */ uuidRegex = regexp.MustCompile(_uuidRegex)

// isValidUUID takes in a string and returns true if it is a valid Version 4 UUID.
// Otherwise it returns false.
func IsValidUUID(uuid string) (isValid bool) {
	return uuidRegex.MatchString(uuid)
}
