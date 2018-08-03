package helpers

import (
	"net/http"
	"testing"
)

type headerTest struct {
	header   http.Header
	checkFor string
	expected bool
}

func genTestHeaders() []headerTest {
	// Helper to get an instance of http.Header
	p := func(val string) http.Header {
		h := http.Header{}
		h.Add("Accept", val)
		return h
	}

	tests := []headerTest{
		headerTest{p(""), "text/html", false},
		headerTest{p("Robert'); DROP TABLE Students;--"), "text/html", false},
		headerTest{p("text/html"), "text/html", true},
		headerTest{p("text/html"), "text/plain", false},
		headerTest{p("application/json"), "text/plain", false},
		headerTest{p("application/json"), "application/json", true},
		headerTest{p("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"), "application/xhtml+xml", true},
	}

	return tests
}

func TestCheckIfAcceptable(t *testing.T) {
	tests := genTestHeaders()

	for _, test := range tests {
		result := HTTPAcceptCheck(test.checkFor, test.header)
		if result != test.expected {
			t.Fatalf("Result for \"%s\" is \"%t\" but should be \"%t\" for %v", test.checkFor, result, test.expected, test.header)
		}
	}
}

func BenchmarkCheckIfAcceptable(b *testing.B) {
	tests := genTestHeaders()

	for n := 0; n < b.N; n++ {
		for _, test := range tests {
			result := HTTPAcceptCheck(test.checkFor, test.header)
			if result != test.expected {
				b.Fatalf("Result for \"%s\" is \"%t\" but should be \"%t\" for %v", test.checkFor, result, test.expected, test.header)
			}
		}
	}
}
