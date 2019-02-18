package helpers

import (
	"net/http"

	"github.com/golang/gddo/httputil/header"
)

// HTTPAcceptCheck takes in the HTTP request Accept header and returns boolean
// if the requested mime-type is found
// TODO support `text/*`? or wait for GO to implement this check since parsing/
// processing this header is at least a couple of RFCs
func HTTPAcceptCheck(acceptable string, value http.Header) bool {
	arr := header.ParseList(value, "Accept")

	for _, val := range arr {
		if val == acceptable {
			return true
		}
	}

	return false
}
