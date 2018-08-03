package helpers

import (
	"regexp"
)

const _uuidRegex = "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"

var uuidRegex = regexp.MustCompile(_uuidRegex)

// IsValidUUID checks if given string is a valid Version 4 UUID.
func IsValidUUID(uuid string) (isValid bool) {
	return uuidRegex.MatchString(uuid)
}
