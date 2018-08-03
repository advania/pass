package main

import (
	"log"
	"net/http"
	textTemplate "text/template"

	"github.com/meh-is/pass"
	"github.com/meh-is/pass/senders"
)

func main() {
	log.SetFlags(0)

	p := pass.CreatePass()
	emailcfg := senders.CreateEmailcfg(p)

	// Load templates for sender_email
	postEmailTemplate := p.LoadTemplate("create/post_email.html")
	emailTemplate := textTemplate.Must(textTemplate.ParseFiles(p.ResolveTemplatePath("email.txt")))

	// Register any sub request handlers (no need unless we want to alter the main request handler)
	p.RegisterRequestHandler(func(parent http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if senders.EmailHandler(p, rw, r, emailcfg, postEmailTemplate, emailTemplate) {
				return
			}

			// the above code did not handle the request, so the main logic can
			// take over and handle it
			parent.ServeHTTP(rw, r)
		})
	})

	// This command block forever
	pass.Main(p)
}
