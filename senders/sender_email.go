package senders

import (
	"bytes"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/smtp"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/meh-is/pass"
	"github.com/meh-is/pass/helpers"
)

// EmailConfig contains the config required for SendEmail
type EmailConfig struct {
	Sender struct {
		Address string
		Name    string
	}
	Server string
}

// SendEmail sends the templated email to the rcpt
func SendEmail(emailcfg EmailConfig, rcpt string, uuid string, siteURL string, emailTemplate *textTemplate.Template) (err error) {
	emailVars := struct {
		URL           string
		MessageID     string
		MailFromName  string
		MailFrom      string
		MailTo        string
		UUID          string
		UUIDFirst     string
		Now           time.Time
		SubjectFilter func(string, string) string
	}{
		URL:           siteURL,
		MessageID:     fmt.Sprintf("%d.%s", time.Now().UnixNano(), emailcfg.Sender.Address),
		MailFromName:  emailcfg.Sender.Name,
		MailFrom:      emailcfg.Sender.Address,
		MailTo:        rcpt,
		UUID:          uuid,
		UUIDFirst:     strings.Split(uuid, "-")[0],
		Now:           time.Now(),
		SubjectFilter: mime.QEncoding.Encode,
	}

	email := new(bytes.Buffer)
	if templateError := emailTemplate.ExecuteTemplate(email, "base", emailVars); templateError != nil {
		return pass.NewHTTPError(
			http.StatusInternalServerError,
			fmt.Errorf("Unable to render email to %s error: %v", rcpt, templateError),
		)
	}

	if mailErr := smtp.SendMail(emailcfg.Server, nil, emailVars.MailFrom, []string{rcpt}, email.Bytes()); mailErr != nil {
		return pass.NewHTTPError(
			http.StatusInternalServerError,
			fmt.Errorf("Unable to send email to %s using mailserver %s error: %v", rcpt, emailcfg.Server, mailErr),
		)
	}

	fmt.Printf("Sent an email to %s MessageID: %s\n", emailVars.MailTo, emailVars.MessageID)
	return nil
}

// EmailHandler has will handle any url that fits the pattern /<UUIDv4>/email
func EmailHandler(p *pass.Pass, rw http.ResponseWriter, r *http.Request, emailcfg EmailConfig, postEmailTemplate *template.Template, emailTemplate *textTemplate.Template) bool {
	path := strings.Split(r.URL.Path[1:], "/")

	// We only want to handle the url /<UUIDv4>/email and only when it is a post request
	if len(path) == 2 && helpers.IsValidUUID(path[0]) && path[1] == "email" {
		if r.Method != http.MethodPost {
			p.RenderErrorPage(rw, r, pass.NewHTTPError(
				http.StatusMethodNotAllowed,
				fmt.Errorf("This URL only accepts POST requests"),
			))
			return true
		}

		r.ParseForm()

		rcpt := r.PostForm.Get("email")
		if len(rcpt) < 6 {
			p.RenderErrorPage(rw, r, pass.NewHTTPError(
				http.StatusBadRequest,
				fmt.Errorf("E-Mail address is too short to be valid"),
			))
			return true
		}

		if err := SendEmail(emailcfg, rcpt, path[0], p.GetURL(), emailTemplate); err != nil {
			p.RenderErrorPage(rw, r, err)
			return true
		}

		tv := pass.TemplateVariables{}
		tv.Recipient = rcpt
		p.RenderPage(rw, r, postEmailTemplate, tv)

		return true
	}

	return false
}

// CreateEmailcfg Loads addon config, must be done at server startup since this
// will exit the server on parse error
func CreateEmailcfg(p *pass.Pass) EmailConfig {
	var emailcfg EmailConfig
	p.GetConfigForAddon("email", &emailcfg)
	return emailcfg
}
