package main

import (
	"bytes"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/meh-is/pass/helpers"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	textTemplate "text/template"
	"time"
)

type logger struct {
	io.Writer
	timeFormat string
}

func (w logger) Write(b []byte) (n int, err error) {
	if w.timeFormat == "" {
		return w.Writer.Write(b)
	}

	t := fmt.Sprintf("%s ", time.Now().Format(w.timeFormat))
	return w.Writer.Write(append([]byte(t), b...))
}

type passConfiguration struct {
	Addons               map[string]json.RawMessage
	CertFile             string
	CertKey              string
	Configured           bool
	HSTSMaxAge           int
	HSTSPreload          bool
	Hostname             string
	ListenAddress        string
	MailFrom             string
	MailFromName         string
	PDOString            string
	SMTPServer           string
	Secret               string
	SecretDays           int
	TimestampFormat      string
	Title                string
	TrustedProxies       []string
	TrustedProxyIPHeader string
}

type SenderStatus struct {
	Delivered bool `json:"delivered"`
	Status string `json:"status"`
	Time time.Time `json:"time"`
	Err error `json:"err"`

	Inner interface{}
}

type Sender interface {
	Send(rv *requestVariables, recipient string, message string) (id string, err error)
	Status(rv *requestVariables, id string) (status SenderStatus, err error)
}

var senders map[string]Sender

func RegisterSender(name string, s Sender) {
	if senders == nil {
		senders = make(map[string]Sender, 0)
	} else if _, ok := senders[name]; ok {
		log.Panicf("Tried to register sender %s but we already have one for the same name", name)
	}

	_, filename, _, _ := runtime.Caller(1)
	fmt.Printf("Added sending method %s %s\n", name, path.Base(filename))
	senders[name] = s
}

type passError struct {
	error
	location string
}

type passErrorInputValidation struct {
	error
	tooShort bool
	tooLong  bool
}

type httpError struct {
	error
	code int
}

type Database interface {
	Ping()
	Get(uuid string, sitePassword string) (password string, err error)
	Create(password string, expires time.Time, sitePassword string) (uuid string, err error)
	Close()
}

type MustDatabaseConnect struct {
	dbHandle Database
	mutex    sync.Mutex
	connect  func() (db Database, err error)
}

func (nfp *MustDatabaseConnect) doConnect() (err error) {
	nfp.mutex.Lock()
	defer nfp.mutex.Unlock()

	if nfp.dbHandle == nil {
		var err error
		if nfp.dbHandle, err = nfp.connect(); err != nil {
			return err
		}
	}

	return nil
}
func (nfp *MustDatabaseConnect) Ping() {
	if err := nfp.doConnect(); err != nil {
		return
	}

	nfp.dbHandle.Ping()
}
func (nfp *MustDatabaseConnect) Get(uuid string, sitePassword string) (password string, err error) {
	if err := nfp.doConnect(); err != nil {
		return "", err
	}

	return nfp.dbHandle.Get(uuid, sitePassword)
}
func (nfp *MustDatabaseConnect) Create(password string, expires time.Time, sitePassword string) (uuid string, err error) {
	if err = nfp.doConnect(); err != nil {
		return "", err
	}

	return nfp.dbHandle.Create(password, expires, sitePassword)
}
func (nfp *MustDatabaseConnect) Close() {
	nfp.mutex.Lock()
	defer nfp.mutex.Unlock()

	if nfp.dbHandle != nil {
		nfp.dbHandle.Close()
		nfp.dbHandle = nil
	}
}
func NewMustDatabaseConnect(connect func() (db Database, err error)) (dbc *MustDatabaseConnect) {
	return &MustDatabaseConnect{
		dbHandle: nil,
		connect:  connect,
	}
}

type DatabaseConnection struct {
	db         *sql.DB
	createStmt *sql.Stmt
	getStmt    *sql.Stmt
}

func (pp *DatabaseConnection) Ping() {
	if err := pp.db.Ping(); err != nil {
		log.Printf("Ping() returned %v\n", err)
	}

	return
}
func (pp *DatabaseConnection) Get(uuid string, sitePassword string) (password string, err error) {
	var result *sql.Rows

	if result, err = pp.getStmt.Query(uuid, sitePassword); err != nil {
		return "", passError{
			error:    err,
			location: "*DatabaseConnection Get pp.getStmt.Query",
		}
	}
	defer result.Close()

	result.Next()
	result.Scan(&password)

	return password, nil
}
func (pp *DatabaseConnection) Create(password string, expires time.Time, sitePassword string) (uuid string, err error) {
	var result *sql.Rows
	if result, err = pp.createStmt.Query(password, expires, sitePassword); err != nil {
		return "", passError{
			error:    err,
			location: "*DatabaseConnection Create pp.createStmt.Query",
		}
	}
	defer result.Close()

	result.Next()
	result.Scan(&uuid)

	return uuid, nil
}
func (pp *DatabaseConnection) Close() {
	if pp != nil {
		pp.getStmt.Close()
		pp.createStmt.Close()
		pp.db.Close()
	}
}
func NewDatabaseConnectionVariables(sv *serverVariables) (dbConn Database, err error) {
	var db *sql.DB
	db, err = sql.Open("postgres", sv.cfg.PDOString)
	if err != nil {
		return nil, passError{
			error:    err,
			location: "NewDatabaseConnectionVariables sql.Open",
		}
	}

	if err = db.Ping(); err != nil {
		return nil, passError{
			error:    err,
			location: "NewDatabaseConnectionVariables db.Ping",
		}
	}

	if _, err = db.Exec("set session characteristics as transaction isolation level serializable"); err != nil {
		return nil, passError{
			error:    err,
			location: "NewDatabaseConnectionVariables db.Exec transaction isolation level",
		}
	}

	var createStmt *sql.Stmt
	if createStmt, err = db.Prepare("select * from create_password($1, $2, $3)"); err != nil {
		return nil, passError{
			error:    err,
			location: "NewDatabaseConnectionVariables db.Prepare createStmt",
		}
	}

	var getStmt *sql.Stmt
	if getStmt, err = db.Prepare("select * from get_password($1, $2)"); err != nil {
		return nil, passError{
			error:    err,
			location: "NewDatabaseConnectionVariables db.Prepare getStmt",
		}
	}

	return &DatabaseConnection{
		db:         db,
		createStmt: createStmt,
		getStmt:    getStmt,
	}, err
}

type baseTemplateVariables struct {
	Page_URL          string
	Page_Title        string
	CSS_IntegrityHash string
	JS_IntegrityHash  string
	TemplateVariables *templateVariables
}
type templateVariables struct {
	FormURL        string
	ReturnedString string
	UUIDPrefix     string
	SenderId       string
	ErrorString    string
	Expires        time.Time
}

var contentSecurityPolicy = strings.Join([]string{
	"default-src 'none';",
	"img-src 'self';",
	"style-src 'self';",
	"script-src 'self';",
	"connect-src 'self';",
	"form-action 'self';",
	"frame-ancestors 'none';",
	"block-all-mixed-content;",
	"sandbox allow-scripts allow-forms allow-same-origin;",
	"require-sri-for script style;",
	"base-uri 'none';",
}, " ")

var featurePolicy = strings.Join([]string{
	"accelerometer 'none';",
	"ambient-light-sensor 'none';",
	"autoplay 'none';",
	"camera 'none';",
	"encrypted-media 'none';",
	"fullscreen 'none';",
	"geolocation 'none';",
	"gyroscope 'none';",
	"magnetometer 'none';",
	"microphone 'none';",
	"midi 'none';",
	"payment 'none';",
	"picture-in-picture 'none';",
	"speaker 'none';",
	"usb 'none';",
	"vr 'none';",
}, " ")

// generateSecurityHeaders generates the securityHeaders to be used for every request
func generateSecurityHeaders(sv *serverVariables) {
	sv.securityHeaders = make(map[string]string)
	sv.securityHeaders["Content-Type"] = "text/html; charset=utf-8"

	sv.securityHeaders["Access-Control-Allow-Origin"] = fmt.Sprintf("https://%s/", sv.cfg.Hostname)
	sv.securityHeaders["Strict-Transport-Security"] = "max-age=9001;"
	sv.securityHeaders["Content-Security-Policy"] = contentSecurityPolicy
	sv.securityHeaders["Feature-Policy"] = featurePolicy
	sv.securityHeaders["Expect-CT"] = "max-age=3600, enforce"
	sv.securityHeaders["Referrer-Policy"] = "no-referrer"
	sv.securityHeaders["X-Content-Type-Options"] = "nosniff"
	sv.securityHeaders["X-Frame-Options"] = "deny"
	sv.securityHeaders["X-XSS-Protection"] = "1; mode=block"
}

// serverError takes in any error this program is designed to handle.
//
// It returns a boolean userRecoverable to state if the error is a server side
// problem, or something the user sent that was malformed, and the string to be
// displayed to the user, unless we choose not to display it for obscurity.
func serverError(rv *requestVariables, err error) (statusCode int, txt string) {
	if passErr, okPassErr := err.(passError); okPassErr {
		if pqErr, okPqErr := passErr.error.(*pq.Error); okPqErr {
			switch pqErr.Constraint {
			case "password_expires_low_limit":
				fallthrough
			case "password_expires_high_limit":
				rv.sv.errorLogger.Printf("You set the expiry of passwords too small or large and violated the %v constraint\n", pqErr.Constraint)
				return http.StatusInternalServerError, ""
			case "password_data_length_limit":
				return http.StatusBadRequest, "The password you submitted is too long, be reasonable!"
			}

			rv.sv.errorLogger.Printf("pqErr: %s (Error at: %v)", passErr.location, passErr)

			if pqErr.Routine == "ClientAuthentication" {
				return http.StatusInternalServerError, ""
			}

			return http.StatusInternalServerError, "You caused an unknown database error... good job..."
		} else if netErr, okNetErr := passErr.error.(net.Error); okNetErr {
			if opErr, okOpErr := netErr.(*net.OpError); okOpErr {
				if dnsErr, okDnsErr := opErr.Err.(*net.DNSError); okDnsErr {
					rv.sv.errorLogger.Printf("DNS Lookup error, temporary: %t, timeout: %t: %v", dnsErr.IsTemporary, dnsErr.IsTimeout, dnsErr)
					return http.StatusInternalServerError, ""
				} else if osSyscallErr, okOsSyscallErr := opErr.Err.(*os.SyscallError); okOsSyscallErr {
					rv.sv.errorLogger.Printf("Syscall %s resulted in code %d during %s in: %v", osSyscallErr.Syscall, osSyscallErr.Err, opErr.Op, opErr)
					return http.StatusInternalServerError, ""
				}

				rv.sv.errorLogger.Printf("Generic *net.OpError: %v", opErr)
				return http.StatusInternalServerError, ""
			}

			rv.sv.errorLogger.Printf("net.Error: %v", netErr)
			return http.StatusInternalServerError, ""
		} else if osPathError, okOsPathError := passErr.error.(*os.PathError); okOsPathError {
			rv.sv.errorLogger.Printf("*os.PathError: %v", osPathError)
			return http.StatusInternalServerError, ""
		} else if passErr.error.Error() == "len(submittedPassword) < 6" {
			return http.StatusBadRequest, "Password must be at least 6 characters."
		} else {
			rv.sv.errorLogger.Printf("passErr: %v", passErr)
			return http.StatusInternalServerError, ""
		}
	}

	if ivErr, okIvErr := err.(passErrorInputValidation); okIvErr {
		if ivErr.tooLong || ivErr.tooShort {
			s := "long"

			if ivErr.tooShort {
				s = "short"
			}

			return http.StatusBadRequest, fmt.Sprintf("Your password is too %s", s)
		}

		// fallthrough, on purpose
	}

	if httpErr, okHttpErr := err.(httpError); okHttpErr {
		rv.sv.errorLogger.Printf("httpErr: %v", err)
		return httpErr.code, httpErr.Error()
	}

	rv.sv.errorLogger.Printf("UNHANDLED Error: %v", err)
	return http.StatusInternalServerError, ""
}

func sendEmail(rv *requestVariables, rcpt string, expires time.Time) error {
	if len(rcpt) < 6 {
		// a@a.is -- does it ever get shorter? maybe domainless but i wont accept those
		return passError{
			error:    errors.New("len(rcpt) < 6"),
			location: "E-Mail address is too short to be valid",
		}
	}

	emailVars := struct {
		Title        string
		URL          string
		MessageID    string
		MailFromName string
		MailFrom     string
		MailTo       string
		Uuid         string
		UuidFirst    string
		Now          time.Time
		Expires      time.Time
	}{
		Title:        rv.sv.cfg.Title,
		URL:          fmt.Sprintf("https://%s", rv.sv.cfg.Hostname),
		MessageID:    fmt.Sprintf("%d.%d@%s", time.Now().UnixNano(), os.Getpid(), rv.sv.cfg.Hostname),
		MailFromName: rv.sv.cfg.MailFromName,
		MailFrom:     rv.sv.cfg.MailFrom,
		MailTo:       rcpt,
		Uuid:         rv.path[0],
		UuidFirst:    strings.Split(rv.path[0], "-")[0],
		Now:          time.Now(),
		Expires:      expires,
	}

	templates := textTemplate.Must(textTemplate.ParseFiles("templates/email.txt"))

	email := new(bytes.Buffer)
	if templateError := templates.ExecuteTemplate(email, "base", emailVars); templateError != nil {
		return passError{
			error:    templateError,
			location: "Email failed to render, please contact the system administrator",
		}
	}

	if mailErr := smtp.SendMail(rv.sv.cfg.SMTPServer, nil, rv.sv.cfg.MailFrom, []string{rcpt}, email.Bytes()); mailErr != nil {
		return passError{
			error:    mailErr,
			location: fmt.Sprintf("Password could not be sent via %s", rv.sv.cfg.SMTPServer),
		}
	}

	rv.sv.logger.Printf("Sent an email to %s successfully\n", emailVars.MailTo)
	return nil
}

func sendSms(rv *requestVariables, rcpt string, uuid string, sendSecurely bool) (smsId string, err error) {
	if len(rcpt) < 5 {
		// 33333?? -- does it ever get shorter?
		return smsId, httpError{code: 400, error: errors.New("Phone number is too short to be valid")}
	}

	payload := fmt.Sprintf("https://%s/%s", rv.sv.cfg.Hostname, uuid)
	if !sendSecurely {
		rv.sv.logger.Printf("Sending insecure/plaintext password to %s", rcpt)

		if payload, err = rv.sv.db.Get(uuid, rv.sv.cfg.Secret); err != nil {
			return smsId, httpError{code: 400, error: err}
		}
	}

	if smsId, err = senders["sms"].Send(rv, rcpt, payload); err != nil {
		return smsId, httpError{code: 400, error: err}
	}

	return smsId, err
}

func getSmsStatus(rv *requestVariables, smsId string) (err error) {
	preventTemplate := errors.New("json")

	if len(smsId) != 36 {
		rv.w.WriteHeader(http.StatusBadRequest)
		rv.w.Write([]byte("len(smsId) != 36"))

		return preventTemplate
	}

	var smsStatus SenderStatus
	if smsStatus, err = senders["sms"].Status(rv, smsId); err != nil {
		rv.w.WriteHeader(http.StatusInternalServerError)
		rv.w.Write([]byte("Status(...) returned err"))
		rv.sv.errorLogger.Println(err)

		return preventTemplate
	}

	var statusObject *smsStatusResult
	var ok bool
	if statusObject, ok = smsStatus.Inner.(*smsStatusResult); !ok {
		rv.w.WriteHeader(http.StatusInternalServerError)
		rv.w.Write([]byte("smsStatus.Inner.(smsStatusResult) returned !ok"))

		return preventTemplate
	}

	var j []byte
	if j, err = json.MarshalIndent(statusObject, "", "  "); err != nil {
		rv.w.WriteHeader(http.StatusInternalServerError)
		rv.w.Write([]byte("json.MarshalIndent(smsStatus, ...) returned err"))

		return preventTemplate
	}

	rv.w.WriteHeader(http.StatusOK)
	rv.w.Write(j)

	return preventTemplate
}

func get(rv *requestVariables) (string, *templateVariables, error) {
	tv := &templateVariables{}
	if rv.r.Method == "GET" {
		t := "templates/get/get.html"
		tv.FormURL = ""

		return t, tv, nil
	}

	t := "templates/get/post.html"

	var password string
	var err error

	entirePath := strings.Split(rv.r.URL.Path[1:], "/")
	uuid := entirePath[0]

	if password, err = rv.sv.db.Get(uuid, rv.sv.cfg.Secret); err != nil {
		return t, tv, err
	}

	if len(password) == 0 {
		oldPrefix := rv.sv.errorLogger.Prefix()
		rv.sv.errorLogger.SetPrefix("[WRN] ")
		rv.sv.errorLogger.Printf("ip: %s requested a UUID but it was not found\n", rv.userIP)
		rv.sv.errorLogger.SetPrefix(oldPrefix)

		t := "templates/errors/pw_not_found.html"
		tv.ReturnedString = string(uuid)
		return t, tv, err
	}

	tv.ReturnedString = string(password)

	return t, tv, err
}

func create(rv *requestVariables) (string, *templateVariables, error) {
	tv := &templateVariables{}
	if rv.r.Method == "GET" {
		t := "templates/create/get.html"
		tv.FormURL = "/"

		return t, tv, nil
	}

	var uuid string
	var err error
	t := "templates/create/post.html"

	var submittedPassword = rv.r.PostForm.Get("secret")

	if len([]rune(submittedPassword)) < 6 {
		return t, tv, passError{
			error:    errors.New("len(submittedPassword) < 6"),
			location: "Password must be at least 6 characters",
		}
	}

	passwordExpiresAt := time.Now().UTC().AddDate(0, 0, rv.sv.cfg.SecretDays)

	if uuid, err = rv.sv.db.Create(submittedPassword, passwordExpiresAt, rv.sv.cfg.Secret); err != nil {
		return t, tv, err
	}

	if len(uuid) == 0 {
		return t, tv, passError{
			error:    errors.New("uuid length == 0"),
			location: "Password not created for an unknown reason",
		}
	}

	tv.ReturnedString = uuid
	tv.UUIDPrefix = strings.Split(uuid, "-")[0]
	tv.Expires = passwordExpiresAt

	return t, tv, nil
}

// getIntegrityHash takes in a filename and returns a sha512 hash encoded as base64
// used for Subresource Integrity (SRI)
func getIntegrityHash(sv *serverVariables, filename string) (hash string) {
	var f *os.File
	var err error
	if f, err = os.Open(filename); err != nil {
		sv.errorLogger.Fatalln(err)
	}
	defer f.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, f); err != nil {
		sv.errorLogger.Fatalln(err)
	}

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// logRequest logs any incoming request to stdout
// it also ensures any UUIDs in the url get masked out
func logRequest(rv *requestVariables) {
	// Masks UUIDs from the log
	maskedPath := make([]string, len(rv.path))
	copy(maskedPath, rv.path)

	if helpers.IsValidUUID(maskedPath[0]) {
		maskedPath[0] = "<UUIDv4>"
	}

	// yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy // TODO check for the dashes? figure out the UUID version?
	if len(maskedPath) == 3 && len(maskedPath[2]) == 36 {
		maskedPath[2] = "<UUID>"
	}

	remote := rv.userIP
	if rv.remoteIsTrustedProxy {
		remote = rv.currentProxyIP
	}

	logTemplate := fmt.Sprintf("remote: %s, proxy: %t", remote, rv.remoteIsTrustedProxy)
	if rv.remoteIsTrustedProxy {
		logTemplate += fmt.Sprintf(", userIP: %s", rv.userIP)
	}
	logTemplate += fmt.Sprintf(", method: %s, path: /%s", rv.r.Method, strings.Join(maskedPath, "/"))

	rv.sv.logger.Println(logTemplate)
}

// innerTemplate tv err
// handleUser handles a valid user request and routes it to the appropriate handler, or returns an error
func handleUser(rv *requestVariables) (innerTemplate string, tv *templateVariables, err error) {
	innerTemplate = "templates/errors/500.html"
	tv = &templateVariables{}

	if rv.r.Method == "GET" {
		if len(rv.path) == 1 && rv.path[0] == "" {
			// GET:  /
			//       = ACL Create new password form
			innerTemplate, tv, err = create(rv)
		} else if len(rv.path) == 1 && helpers.IsValidUUID(rv.path[0]) {
			// GET:  /some-uuid-from-link
			//       = Public Get password form
			innerTemplate, tv, err = get(rv)
		} else {
			err = httpError{code: 404, error: errors.New("Not a valid url for GET method")}
		}
	} else if rv.r.Method == "POST" {
		rv.r.ParseForm()

		if len(rv.path) == 1 && rv.path[0] == "" {
			// POST: /
			//       = ACL Perform create new password, offer delivery options
			innerTemplate, tv, err = create(rv)
		} else if len(rv.path) == 1 && helpers.IsValidUUID(rv.path[0]) {
			// POST: /some-uuid-from-link
			//       = Public Get actual password and display
			innerTemplate, tv, err = get(rv)
		} else if len(rv.path) == 2 && helpers.IsValidUUID(rv.path[0]) && rv.path[1] == "email" {
			// POST: /some-uuid-from-link/email
			//       = ACL Send email with link to /some-uuid-from-link

			rcpt := rv.r.PostForm.Get("email")
			if len(rcpt) < 5 {
				err = httpError{code: 400, error: errors.New("Recipient is invalid.")}
			}

			var expires time.Time
			if expires, err = time.Parse("2006-01-02 15:04:05", rv.r.PostForm.Get("expires")); err != nil {
				err = httpError{code: 400, error: errors.New("expires is badly formed")}
				return innerTemplate, tv, err
			}
			tv.ReturnedString = rcpt
			tv.UUIDPrefix = strings.Split(rv.path[0], "-")[0]

			if err = sendEmail(rv, rcpt, expires); err == nil {
				innerTemplate = "templates/create/post_email.html"
			}
		} else if len(rv.path) == 2 && helpers.IsValidUUID(rv.path[0]) && rv.path[1] == "sms" {
			// POST: /some-uuid-from-link/sms
			//       = ACL Send sms with link to /some-uuid-from-link

			rcpt := rv.r.PostForm.Get("phone")
			if len(rcpt) < 5 {
				err = httpError{code: 400, error: errors.New("Recipient is invalid.")}
			}

			sendSecurely := rv.r.PostForm.Get("sendSecurely")
			if len(rcpt) != 1 {
				err = httpError{code: 400, error: errors.New("Secure flag is invalid.")}
			}

			secure := true
			if sendSecurely != "1" {
				secure = false
			}

			var smsId string
			if smsId, err = sendSms(rv, rcpt, rv.path[0], secure); err == nil {
				tv.ReturnedString = rcpt
				tv.SenderId = smsId
				innerTemplate = "templates/create/post_sms.html"
			}
		} else if len(rv.path) == 3 && helpers.IsValidUUID(rv.path[0]) && rv.path[1] == "sms" && len(rv.path[2]) > 10 {
			// sends json directly to the requester
			if err = getSmsStatus(rv, rv.path[2]); err == nil {
				// ensure the error handler in handler() does not send the template to the user
				// since we are sending json directly to the user
				err = errors.New("json")
			}
		} else {
			err = httpError{code: 404, error: errors.New("Not a valid url for POST method")}
		}
	} else {
		err = httpError{code: 405, error: errors.New("Not a valid method")}
	}

	return innerTemplate, tv, err
}

func getBaseTemplateVariables(rv *requestVariables) (btv *baseTemplateVariables) {
	tv := &templateVariables{}

	return &baseTemplateVariables{
		Page_URL:          fmt.Sprintf("https://%s", rv.sv.cfg.Hostname),
		Page_Title:        rv.sv.cfg.Title,
		CSS_IntegrityHash: rv.sv.integrityHashes["css"],
		JS_IntegrityHash:  rv.sv.integrityHashes["js"],
		TemplateVariables: tv,
	}
}

func renderPage(innerTemplate string, rv *requestVariables, btv *baseTemplateVariables) {
	templates := template.Must(template.ParseFiles(
		"templates/layout/base.html",
		"templates/layout/dbError.html",
		innerTemplate))

	if templateError := templates.ExecuteTemplate(rv.w, "base", btv); templateError != nil {
		rv.sv.errorLogger.Println(templateError)
		fmt.Fprintln(rv.w, "Error rendering page!")
	}
}

func resolveClientIP(rv *requestVariables) (err error) {
	var ipString string
	if ipString, _, err = net.SplitHostPort(rv.r.RemoteAddr); err != nil {
		return err
	}

	ip := net.ParseIP(ipString)

	if isTrustedProxy := helpers.IpNetArrayContainsIP(rv.sv.trustedProxies, ip); isTrustedProxy {
		rv.remoteIsTrustedProxy = isTrustedProxy
		rv.currentProxyIP = ip

		if h, ok := rv.r.Header[rv.sv.cfg.TrustedProxyIPHeader]; ok {
			if ip = net.ParseIP(h[0]); ip == nil {
				return errors.New(fmt.Sprintf("IP Address %s of client via trusted proxy failed to parse", h[0]))
			}
		} else {
			// Proxies often send requests to backend for alive checking but
			// they usually don't add this header there, so, just allow it, we
			// trust them anyway... right?

			// But when they do so, they are not proxying, they are clients
			rv.remoteIsTrustedProxy = false
		}
	}

	rv.userIP = ip
	return err
}

func handler(rv *requestVariables) {
	if err := resolveClientIP(rv); err != nil {
		rv.sv.errorLogger.Printf("Remote client %s failed to parse %v, logging may be incorrect!\n", rv.r.RemoteAddr, err)
	}

	rv.path = strings.Split(rv.r.URL.Path[1:], "/")

	for key, value := range rv.sv.securityHeaders {
		rv.w.Header().Set(key, value)
	}

	if rv.r.Method == "GET" {
		switch rv.path[0] {
		case "favicon.ico":
			rv.w.Header().Set("Content-Type", "image/x-icon")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			http.ServeFile(rv.w, rv.r, "static/favicon.ico")
			return

		case "css":
			rv.w.Header().Set("Content-Type", "text/css")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			http.ServeFile(rv.w, rv.r, "static/css.css")
			return

		case "js":
			rv.w.Header().Set("Content-Type", "application/javascript")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			http.ServeFile(rv.w, rv.r, "static/js.js")
			return

		case "logo":
			rv.w.Header().Set("Content-Type", "image/png")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			http.ServeFile(rv.w, rv.r, "static/logo_header.png")
			return

		case "robots.txt":
			rv.w.Header().Set("Content-Type", "text/plain")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			rv.w.Write([]byte("User-agent: *\nDisallow: /"))
			return

		case "ping":
			rv.w.Header().Set("Cache-Control", "max-age=60")
			// Takes ~42 seconds if db is unresponsive, use it to check for it using client side js
			rv.sv.db.Ping()
			return
		}
	}

	if rv.r.Method == "POST" {
		// Completely stop all client side caching of POST result pages
		// Also intentionally disables the use of the "back" button to pages containing sensitive content
		rv.w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		rv.w.Header().Set("Pragma", "no-cache")
		rv.w.Header().Set("Expires", "0")
	}

	var err error
	var innerTemplate string

	btv := getBaseTemplateVariables(rv)

	innerTemplate, btv.TemplateVariables, err = handleUser(rv)

	if err != nil {
		if err.Error() == "json" {
			return
		}

		httpStatusCode, errStr := serverError(rv, err)

		rv.w.WriteHeader(httpStatusCode)
		innerTemplate = fmt.Sprintf("templates/errors/%d.html", httpStatusCode)

		btv.TemplateVariables.ReturnedString = errStr
	}

	renderPage(innerTemplate, rv, btv)
}

type serverVariables struct {
	trustedProxies []*net.IPNet
	cfg            passConfiguration

	logger      *log.Logger
	errorLogger *log.Logger

	integrityHashes map[string]string
	securityHeaders map[string]string

	db Database
}

type requestVariables struct {
	sv *serverVariables

	remoteIsTrustedProxy bool
	currentProxyIP       net.IP
	userIP               net.IP

	path []string

	w http.ResponseWriter
	r *http.Request
}

func createBlankConfig(configFileName string) {
	var cfg passConfiguration
	var err error

	cfg = passConfiguration{
		Addons:               nil,
		CertFile:             "example.com.crt",
		CertKey:              "example.com.key",
		HSTSMaxAge:           3600,
		HSTSPreload:          false,
		Hostname:             "example.com",
		ListenAddress:        "[::1]:443",
		MailFrom:             "you@example.com",
		MailFromName:         "Mr. Beikon",
		PDOString:            "host=db.example.com. dbname=passwords user=password_frontend sslmode=verify-full sslrootcert=leroot.cer",
		SMTPServer:           "smtp.example.com:smtp",
		Secret:               "set once, if changed, all passwords become unusable (must be at least 100 (random) characters!)",
		SecretDays:           7,
		TimestampFormat:      "2006-01-02 15:04:05",
		Title:                "MEH Pass v0.3",
		TrustedProxies:       []string{"192.168.1.2/32", "192.168.2.2/32"},
		TrustedProxyIPHeader: "X-Forwarded-For",
		Configured:           false,
	}

	var b []byte
	if b, err = json.MarshalIndent(cfg, "", "  "); err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("---\n%s\n---\n", b)
	log.Fatalf("Config file (%s) was not found, here's a default one for you, please fill it in and try again.\n", configFileName)
}

func loadConfig(configFileName string) (cfg passConfiguration) {
	var file *os.File
	var err error
	if file, err = os.Open(configFileName); err != nil {
		createBlankConfig(configFileName)
	}

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&cfg); err != nil {
		log.Fatalln(err)
	}

	if !cfg.Configured {
		log.Fatalf("You have not finished configuring %s, do so and remember to set Configured to true ;)\n", configFileName)
	}

	if len(cfg.Secret) < 64 {
		log.Fatalln("Site secret shorter than 64 characters, please make it at least 64 characters!")
	}

	// Do we trust the proxy in front of us?
	fmt.Println("Loading trusted proxies")
	var asd []*net.IPNet
	if asd, err = helpers.StringArrayToIPNet(cfg.TrustedProxies); err != nil {
		log.Fatalf("Trusted proxy list failed to parse")
	}
	fmt.Printf("%d prefixes added\n", len(asd))

	return cfg
}

func RecoverWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() {
			r := recover()
			if r != nil {
				switch t := r.(type) {
				case string:
					err = errors.New(t)
				case error:
					err = t
				default:
					err = errors.New("Unknown error")
				}
				debug.PrintStack()
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}


type PassHandler interface {
	Handle(hi http.Handler) (ho http.Handler)
}

var passhandlers []PassHandler

func RegisterPassHandler(s PassHandler) {
	if passhandlers == nil {
		passhandlers = make([]PassHandler, 0)
	}

	_, filename, _, _ := runtime.Caller(1)
	fmt.Printf("Added PassHandler %s %s\n", path.Base(filename))
	passhandlers = append(passhandlers, s)
}

func main() {
	sv := &serverVariables{}

	sv.cfg = loadConfig("pass.json")

	sv.logger = log.New(&logger{os.Stdout, sv.cfg.TimestampFormat}, "[INF] ", 0)
	sv.errorLogger = log.New(&logger{os.Stderr, sv.cfg.TimestampFormat}, "[ERR] ", 0)

	sv.trustedProxies = make([]*net.IPNet, 0)
	sv.trustedProxies, _ = helpers.StringArrayToIPNet(sv.cfg.TrustedProxies)

	if senders == nil {
		sv.logger.Println("No senders added, only link will be available")
	}

	sv.integrityHashes = make(map[string]string)
	sv.integrityHashes["css"] = getIntegrityHash(sv, "static/css.css")
	sv.integrityHashes["js"] = getIntegrityHash(sv, "static/js.js")

	generateSecurityHeaders(sv)

	sv.db = NewMustDatabaseConnect(func() (Database, error) {
		return NewDatabaseConnectionVariables(sv)
	})
	defer sv.db.Close()

	http.Handle("/", RecoverWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rv := new(requestVariables)
		rv.sv = sv
		rv.w = w
		rv.r = r

		handler(rv)
		// TODO: log status code and bytes transferred
		logRequest(rv)
	})))

	sv.logger.Output(1, fmt.Sprintf("%s: Startup!\n", sv.cfg.Title))

	server := &http.Server{
		Addr:              sv.cfg.ListenAddress,
		ErrorLog:          sv.errorLogger,
		IdleTimeout:       time.Second * 60,
		MaxHeaderBytes:    100 * 1000,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second * 120,
	}

	sv.errorLogger.Fatalf("Server failed to start or crashed: %v",
		server.ListenAndServeTLS(sv.cfg.CertFile, sv.cfg.CertKey),
	)

	sv.errorLogger.Fatalln("Somehow, the server exited, should be impossible")
}
