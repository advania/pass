package pass

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/meh-is/pass/helpers"

	"github.com/lib/pq"
)

type passConfiguration struct {
	Addons      map[string]json.RawMessage
	Certificate struct {
		File string
		Key  string
	}
	HSTS struct {
		MaxAge            int
		IncludeSubDomains bool
		Preload           bool
	}
	Hostname       string
	ListenAddress  string
	PDOString      string
	Secret         string
	PasswordLength struct {
		Min int
		Max int
	}
	MaxEntryLength       int
	SecretDays           int
	TemplatePath         string
	Title                string
	TrustedProxies       []string
	TrustedProxyIPHeader string
}

type httpError struct {
	error
	code int
}

type baseTemplateVariables struct {
	PageURL           string
	PageTitle         string
	CSSIntegrityHash  string
	JSIntegrityHash   string
	TemplateVariables interface{}
}

// TemplateVariables TODO split to template specific structs
type TemplateVariables struct {
	FormURL     string `json:"-"`
	URL         string `json:"url,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Recipient   string `json:"recipient,omitempty"`
	SenderID    string `json:"senderid,omitempty"`
	Secret      string `json:"secret,omitempty"`
	ErrorString string `json:"-"`
}

var contentSecurityPolicyHTML = strings.Join([]string{
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

var contentSecurityPolicyJSON = strings.Join([]string{
	"default-src 'none';",
	"frame-ancestors 'none';",
	"block-all-mixed-content;",
	"sandbox",
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
	"sync-xhr 'none';",
	"sync-script 'none';",
	"usb 'none';",
	"vr 'none';",
}, " ")

// generateSecurityHeaders generates the http securityHeaders to be outputted
// as http headers before every request
func (p *Pass) generateSecurityHeaders() {
	p.sv.securityHeaders = map[string]string{}
	// HSTS
	p.sv.securityHeaders["Strict-Transport-Security"] = fmt.Sprintf("max-age=%d", p.sv.cfg.HSTS.MaxAge)
	if p.sv.cfg.HSTS.IncludeSubDomains {
		p.sv.securityHeaders["Strict-Transport-Security"] += "; includeSubDomains"
	}
	if p.sv.cfg.HSTS.Preload {
		p.sv.securityHeaders["Strict-Transport-Security"] += "; preload"
	}

	p.sv.securityHeaders["Access-Control-Allow-Origin"] = p.GetURL()
	p.sv.securityHeaders["Feature-Policy"] = featurePolicy
	p.sv.securityHeaders["Referrer-Policy"] = "no-referrer"
	p.sv.securityHeaders["X-Content-Type-Options"] = "nosniff"
	p.sv.securityHeaders["X-Frame-Options"] = "deny"
	p.sv.securityHeaders["X-XSS-Protection"] = "1; mode=block"
}

// serverError takes in any error this program is designed to handle.
//
// It returns if the error is a server side problem, or something the user sent
// that was malformed, and the string to be displayed to the user, unless we
// choose not to display it for obscurity.
func (p *Pass) serverError(err error) (statusCode int, t *template.Template, txt string) {
	switch e := err.(type) {
	case *net.OpError:
		switch e := e.Err.(type) {
		case *net.DNSError:
			log.Printf("DNS Lookup error, temporary: %t, timeout: %t: %v", e.IsTemporary, e.IsTimeout, e)
		case *os.SyscallError:
			log.Printf("Syscall %s resulted in code %d in: %v", e.Syscall, e.Err, e)
		default:
			log.Printf("net.OpError: %v", e)
		}
	case net.Error:
		log.Printf("net.Error: %v", e)
	case *pq.Error:
		log.Printf("pq.Error: %v", e)
	case *os.PathError:
		log.Printf("os.PathError: %v", e)
	case httpError:
		if e.Error() == "UUID not found" {
			return http.StatusNotFound, p.sv.templates.ErrorsPwNotFound, e.Error()
		}

		switch e.code {
		case http.StatusBadRequest:
			return e.code, p.sv.templates.Errors400, e.Error()
		case http.StatusNotFound:
			return e.code, p.sv.templates.Errors404, e.Error()
		case http.StatusMethodNotAllowed:
			return e.code, p.sv.templates.Errors405, e.Error()
		default:
			log.Printf("httpErr: %v", err)
		}
	default:
		log.Printf("UNHANDLED Error: %v", err)
	}

	return http.StatusInternalServerError, p.sv.templates.Errors500, ""
}

// NewHTTPError returns an instance of httpError which is required for
// RenderErrorPage for proper display and error logging
func NewHTTPError(code int, parentError error) error {
	return httpError{code: code, error: parentError}
}

// ResolveTemplatePath returns the full path to the requested template file
func (p *Pass) ResolveTemplatePath(templateSubPath string) string {
	resolvedTemplatePath := filepath.Join(p.sv.cfg.TemplatePath, templateSubPath)

	if _, err := os.Stat(resolvedTemplatePath); err != nil {
		log.Fatalln(err)
	}

	return resolvedTemplatePath
}

func get(rv *requestVariables) (t *template.Template, tv *TemplateVariables, err error) {
	tv = &TemplateVariables{}
	if rv.r.Method == http.MethodGet {
		t = rv.sv.templates.GetGet
		tv.FormURL = ""

		return t, tv, nil
	}

	t = rv.sv.templates.GetPost

	password := ""

	entirePath := strings.Split(rv.r.URL.Path[1:], "/")
	uuid := entirePath[0]

	if password, err = rv.sv.db.get(uuid, rv.sv.cfg.Secret); err != nil {
		return t, tv, err
	}

	if len(password) == 0 {
		log.Printf("ip: %s requested a UUID but it was not found\n", rv.userIP)

		tv.UUID = string(uuid)
		return t, tv, NewHTTPError(http.StatusNotFound, fmt.Errorf("UUID not found"))
	}

	tv.Secret = string(password)

	return t, tv, err
}

func create(rv *requestVariables) (*template.Template, *TemplateVariables, error) {
	tv := &TemplateVariables{}
	if rv.r.Method == http.MethodGet {
		t := rv.sv.templates.CreateGet
		tv.FormURL = "/"

		return t, tv, nil
	}

	var uuid string
	var err error
	t := rv.sv.templates.CreatePost

	var submittedPassword = rv.r.PostForm.Get("secret")

	if len([]rune(submittedPassword)) < rv.sv.cfg.PasswordLength.Min ||
		len([]rune(submittedPassword)) > rv.sv.cfg.PasswordLength.Max {
		return t, tv, NewHTTPError(
			http.StatusBadRequest,
			fmt.Errorf("Password must be between %d and %d characters in length",
				rv.sv.cfg.PasswordLength.Min,
				rv.sv.cfg.PasswordLength.Max,
			),
		)
	}

	if uuid, err = rv.sv.db.create(submittedPassword, rv.sv.cfg.Secret); err != nil {
		return t, tv, err
	}

	if len(uuid) == 0 {
		log.Printf("Unable to create password entry in database!")
		return t, tv, NewHTTPError(400, errors.New("An error occurred while creating password entry"))
	}

	tv.UUID = uuid
	tv.URL = fmt.Sprintf("https://%s/%s", rv.sv.cfg.Hostname, string(uuid))

	return t, tv, nil
}

// getIntegrityHash takes in a filename and returns a sha512 hash encoded as base64
// used for Subresource Integrity (SRI)
func (p *Pass) getIntegrityHash(filename string) string {
	var f *os.File
	var err error
	if f, err = os.Open(p.ResolveTemplatePath(filename)); err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, f); err != nil {
		log.Fatalln(err)
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

	fmt.Println(logTemplate)
}

// innerTemplate tv err
// handleUser handles a valid user request and routes it to the appropriate handler, or returns an error
func handleUser(rv *requestVariables) (innerTemplate *template.Template, tv *TemplateVariables, err error) {
	tv = &TemplateVariables{}

	if rv.r.Method == http.MethodGet {
		if len(rv.path) == 1 && rv.path[0] == "" {
			// GET:  /
			//       = ACL Create new password form
			return create(rv)
		} else if len(rv.path) == 1 && helpers.IsValidUUID(rv.path[0]) {
			// GET:  /some-uuid-from-link
			//       = Public Get password form
			return get(rv)
		}

		return rv.sv.templates.Errors404, tv, NewHTTPError(404, errors.New("not a valid url for GET method"))
	} else if rv.r.Method == http.MethodPost {
		rv.r.ParseForm()

		if len(rv.path) == 1 && rv.path[0] == "" {
			// POST: /
			//       = ACL Perform create new password, offer delivery options
			return create(rv)
		} else if len(rv.path) == 1 && helpers.IsValidUUID(rv.path[0]) {
			// POST: /some-uuid-from-link
			//       = Public Get actual password and display
			return get(rv)
		} else {
			return rv.sv.templates.Errors404, tv, NewHTTPError(404, errors.New("Not a valid url for POST method"))
		}
	}

	return rv.sv.templates.Errors405, tv, NewHTTPError(405, errors.New("Not a valid method"))
}

// OutputHeaders will output all security and cache headers required for the
// given request method
func (p *Pass) OutputHeaders(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Completely stop all client side caching of POST result pages
		// Also intentionally disables the use of the "back" button to pages containing sensitive content
		rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		rw.Header().Set("Pragma", "no-cache")
		rw.Header().Set("Expires", "0")
	}

	for key, value := range p.sv.securityHeaders {
		rw.Header().Set(key, value)
	}

	// More restrictive CSP for json requests
	if helpers.HTTPAcceptCheck("application/json", r.Header) {
		rw.Header().Set("Content-Security-Policy", contentSecurityPolicyJSON)
	} else {
		rw.Header().Set("Content-Security-Policy", contentSecurityPolicyHTML)
	}
}

// renderPageJSON does the same as RenderPage, but for json requests
// only called by RenderPage, do not call directly
func (p *Pass) renderPageJSON(rw http.ResponseWriter, r *http.Request, innerTemplate *template.Template, tv interface{}) {
	rw.Header().Add("Content-Type", "application/json")
	if b, err := json.MarshalIndent(tv, "", "  "); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		log.Printf("renderPageJSON err %v\n", err)
	} else {
		rw.Write(b)
	}
}

// RenderPage renders the page using the configured layout and security headers
func (p *Pass) RenderPage(rw http.ResponseWriter, r *http.Request, innerTemplate *template.Template, tv interface{}) {
	p.OutputHeaders(rw, r)

	if helpers.HTTPAcceptCheck("application/json", r.Header) {
		if r.Method != http.MethodPost {
			p.RenderErrorPage(rw, r, NewHTTPError(http.StatusMethodNotAllowed, fmt.Errorf("application/json only accepted over POST requests")))
			return
		}

		p.renderPageJSON(rw, r, innerTemplate, tv)
		return
	}

	btv := &baseTemplateVariables{
		PageURL:           p.GetURL(),
		PageTitle:         p.sv.cfg.Title,
		CSSIntegrityHash:  p.sv.integrityHashes["css"],
		JSIntegrityHash:   p.sv.integrityHashes["js"],
		TemplateVariables: tv,
	}

	if templateError := innerTemplate.ExecuteTemplate(rw, "base", btv); templateError != nil {
		log.Printf("Template did not render: %v", templateError)

		// Assume templating is broken, output error string raw to client
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(rw, "Unexpected error while rendering page!")
	}
}

// renderErrorPageJSON does the same as RenderErrorPage, but for json requests
// only called by RenderErrorPage, do not call directly
func (p *Pass) renderErrorPageJSON(rw http.ResponseWriter, r *http.Request, errStr string) {
	rw.Header().Add("Content-Type", "application/json")
	errorJSON := struct{ Error string }{
		Error: errStr,
	}

	if b, err := json.MarshalIndent(errorJSON, "", "  "); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		log.Printf("renderErrorPageJSON err %v\n", err)
	} else {
		rw.Write(b)
	}
}

// RenderErrorPage outputs a rendered error template, no output must be made
// after a call to this function!
func (p *Pass) RenderErrorPage(rw http.ResponseWriter, r *http.Request, err error) {
	var httpStatusCode int
	var errStr string
	var innerTemplate *template.Template
	httpStatusCode, innerTemplate, errStr = p.serverError(err)

	rw.WriteHeader(httpStatusCode)

	if helpers.HTTPAcceptCheck("application/json", r.Header) {
		p.renderErrorPageJSON(rw, r, errStr)
		return
	}

	tv := TemplateVariables{}
	tv.ErrorString = errStr

	p.RenderPage(rw, r, innerTemplate, tv)
}

// GetURL returns a https link for the configured domain[:port]
func (p *Pass) GetURL() string {
	return fmt.Sprintf("https://%s", p.sv.cfg.Hostname)
}

// GetPassword returns the password stored at the given UUID if any
func (p *Pass) GetPassword(uuid string) (string, error) {
	return p.sv.db.get(uuid, p.sv.cfg.Secret)
}

// GetConfigForAddon returns a struct of the unmarshalled data from the server
// configuration
// If we fail here we exit the program with an error
func (p *Pass) GetConfigForAddon(name string, obj interface{}) {
	if cfg, ok := p.sv.cfg.Addons[name]; ok {
		if err := json.Unmarshal(cfg, &obj); err != nil {
			log.Fatalf("Unable to unmarshal addon config: %v", err)
		}
	} else {
		log.Fatalf("Unable to find addon config for %s: %v", name, obj)
	}
}

// resolveClientIP tries to figure out the actual user IP address
//
// For trusted proxies it uses the configured TrustedProxies array to check if
// the RemoteAddr is a proxy we trust and then check the configured
// TrustedProxyIPHeader for the actual user IP address
//
// Othervise, we consider the RemoteAddr to be the user
func resolveClientIP(rv *requestVariables) {
	var ipString string
	var err error
	if ipString, _, err = net.SplitHostPort(rv.r.RemoteAddr); err != nil {
		log.Printf("Failed net.SplitHostPort failed on %s", rv.r.RemoteAddr)
	}

	ip := net.ParseIP(ipString)

	if isTrustedProxy := helpers.IPNetArrayContainsIP(rv.sv.trustedProxies, ip); isTrustedProxy {
		rv.remoteIsTrustedProxy = isTrustedProxy
		rv.currentProxyIP = ip

		if h, ok := rv.r.Header[rv.sv.cfg.TrustedProxyIPHeader]; ok {
			if ip = net.ParseIP(h[0]); ip == nil {
				log.Printf("The TrustedProxyIPHeader \"%s\" contains \"%s\" which failed to parse\n",
					rv.sv.cfg.TrustedProxyIPHeader,
					h[0],
				)
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
}

// serveStatic sets the appropriate content type and cache control headers
// before sending the file body to the requesting client
func (p *Pass) serveStatic(rv *requestVariables, name string, mimeType string) {
	rv.w.Header().Set("Content-Type", mimeType)
	rv.w.Header().Set("Cache-Control", "max-age=2592000")

	http.ServeFile(rv.w, rv.r, p.ResolveTemplatePath(name))
}

// onBeforeRequest must be called before a request handler attempts to access
// the client IP or the path array
func onBeforeRequest(rv *requestVariables) {
	resolveClientIP(rv)
	rv.path = strings.Split(rv.r.URL.Path[1:], "/")

	logRequest(rv)
}

func handler(p *Pass, rv *requestVariables) {
	if rv.r.Method == http.MethodGet {
		switch rv.path[0] {
		case "favicon.ico":
			p.serveStatic(rv, "static/favicon.ico", "image/x-icon")
			return
		case "css":
			p.serveStatic(rv, "static/css.css", "text/css")
			return
		case "js":
			p.serveStatic(rv, "static/js.js", "application/javascript")
			return
		case "logo":
			p.serveStatic(rv, "static/logo_header.png", "image/png")
			return
		case "robots.txt":
			rv.w.Header().Set("Content-Type", "text/plain")
			rv.w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
			rv.w.Write([]byte("User-agent: *\nDisallow: /"))
			return
		case "ping":
			rv.w.Header().Set("Cache-Control", "max-age=0")
			// Takes ~42 seconds if db is unresponsive, use it to check for it using client side js
			// https://github.com/lib/pq/issues/620
			// returns HTTP 500 if server can be instantly detected as being down
			if err := rv.sv.db.ping(); err != nil {
				log.Printf("db.Ping() returned %v\n", err)
				rv.w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
	}

	innerTemplate, tv, err := handleUser(rv)

	if err != nil {
		p.RenderErrorPage(rv.w, rv.r, err)
	} else {
		p.RenderPage(rv.w, rv.r, innerTemplate, tv)
	}
}

type serverVariables struct {
	trustedProxies []*net.IPNet
	cfg            passConfiguration

	integrityHashes map[string]string
	securityHeaders map[string]string

	db database

	templates parsedTemplates
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

type parsedTemplates struct {
	CreateGet  *template.Template
	CreatePost *template.Template

	GetGet  *template.Template
	GetPost *template.Template

	Errors400        *template.Template
	Errors401        *template.Template
	Errors404        *template.Template
	Errors405        *template.Template
	Errors500        *template.Template
	ErrorsPwNotFound *template.Template
}

func (p *Pass) mustParseInnerTemplate(innerTemplate string) *template.Template {
	innerTemplate = p.ResolveTemplatePath(innerTemplate)

	parsed, err := p.baseTemplate.Clone()
	if err != nil {
		log.Fatalf("mustParseInnerTemplate: Failed parsing template \"%s\" with error: %v", innerTemplate, err)
	}

	return template.Must(parsed.ParseFiles(innerTemplate))
}

// LoadTemplate loads the referenced file and compiles it with the program
// layout specified with TemplatePath
func (p *Pass) LoadTemplate(name string) *template.Template {
	return p.mustParseInnerTemplate(name)
}

func preparseTemplates(p *Pass) {
	p.sv.templates = parsedTemplates{
		CreateGet:  p.LoadTemplate("create/get.html"),
		CreatePost: p.LoadTemplate("create/post.html"),

		GetGet:  p.LoadTemplate("get/get.html"),
		GetPost: p.LoadTemplate("get/post.html"),

		Errors400:        p.LoadTemplate("errors/400.html"),
		Errors404:        p.LoadTemplate("errors/404.html"),
		Errors405:        p.LoadTemplate("errors/405.html"),
		Errors500:        p.LoadTemplate("errors/500.html"),
		ErrorsPwNotFound: p.LoadTemplate("errors/pw_not_found.html"),
	}
}

// loadConfig loads the config file from the given filename
func loadConfig(configFileName string) (cfg passConfiguration, err error) {
	var file *os.File
	if file, err = os.Open(configFileName); err != nil {
		return cfg, fmt.Errorf("Config file (%s) was not found, please create one using the included template", configFileName)
	}

	fmt.Printf("Loading config file \"%s\"\n", configFileName)

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("Unable to decode config file: %v", err)
	}

	if len(cfg.Secret) < 64 {
		return cfg, fmt.Errorf("Site secret shorter than 64 characters, please make it at least 64 characters")
	}

	return cfg, nil
}

// recoverWrap registers a deferred error handler for the http.Handler
// This prevents the entire program from coming down like a ton of bricks if a
// user causes a panic.
// The stacktrace is printed and the corresponding handler dies, but no other
// requests are affected.
func recoverWrap(h http.Handler) http.Handler {
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
					err = fmt.Errorf("recoverWrap Unknown error %T %v", r, r)
				}

				log.Printf("recoverWrap triggered!\n")
				fmt.Printf("Cause: %v\n|\n", err)

				msgStrings := strings.Split(strings.TrimRight(string(debug.Stack()), "\n"), "\n")

				// 7 is to remove the heading and the first 3 frames (2 lines each)
				// because they contain the call to the recoverWrap func and the
				// call to panic() which is useless when _this_ program is the issue
				msgStrings = msgStrings[7:]

				for _, value := range msgStrings {
					fmt.Printf("|\t%s\n", string(value))
				}

				fmt.Printf("|\nEND of wrapped panic\n")

				// We paniced, assume templating is a no-go and just output plaintext error
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
		}()

		h.ServeHTTP(w, r)
	})
}

// RegisterRequestHandler allows an importer to hook the request handler, allows
// a sort of MITM for incoming requests, RequestHandlers must call f with a Pass
// instance if they want the request to continue via the main program logic
func (p *Pass) RegisterRequestHandler(f func(http.Handler) http.Handler) {
	_, filename, line, _ := runtime.Caller(1)
	fmt.Printf("Added RequestHandler %s:%d\n----\n", filename, line)
	p.handler = f(p.handler)
}

// Pass is a struct holding all required variables for wrappers, instanced using
// the CreatePass function
type Pass struct {
	sv           *serverVariables
	baseTemplate *template.Template
	handler      http.Handler
}

// CreatePass returns a pointer to an instance of Pass
// for use in calls to Main(Pass) in main() functions of hooking applications
func CreatePass() *Pass {
	p := &Pass{
		&serverVariables{},
		nil,
		nil,
	}

	configFileName := flag.String("cfg", "pass.json", "A path to the program config file")
	flag.Parse()

	var err error
	if p.sv.cfg, err = loadConfig(*configFileName); err != nil {
		log.Fatalf(err.Error())
	}

	p.sv.trustedProxies = []*net.IPNet{}
	p.sv.trustedProxies, _ = helpers.StringArrayToIPNet(p.sv.cfg.TrustedProxies)

	p.sv.integrityHashes = map[string]string{}
	p.sv.integrityHashes["css"] = p.getIntegrityHash("static/css.css")
	p.sv.integrityHashes["js"] = p.getIntegrityHash("static/js.js")

	p.generateSecurityHeaders()

	p.baseTemplate = template.Must(template.ParseFiles(
		p.ResolveTemplatePath("layout/base.html"),
		p.ResolveTemplatePath("layout/dbError.html"),
	))

	p.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rv := new(requestVariables)
		rv.sv = p.sv
		rv.w = w
		rv.r = r

		onBeforeRequest(rv)
		handler(p, rv)
	})

	return p
}

// Main executes the main program, starts the https server, serves clients
func Main(pass *Pass) {
	sv := pass.sv

	sv.db = newMustDatabaseConnect(func() (database, error) {
		return newDatabaseConnectionVariables(sv)
	})
	defer sv.db.close()

	preparseTemplates(pass)

	http.Handle("/", recoverWrap(pass.handler))

	_, mainApp, _, _ := runtime.Caller(0)
	_, wrapper, _, _ := runtime.Caller(1)

	fmt.Printf("%s: Startup!\n", sv.cfg.Title)
	fmt.Printf("Main program: %s\n", mainApp)
	fmt.Printf("Wrapped by:   %s\n", wrapper)

	// goroutine that runs forever checking the state of the database connection
	// This can not run in the normal process flow because of a bug in the pq
	// module, it is not possible to cancel a query with a timeout
	// https://github.com/lib/pq/issues/620
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			if err := sv.db.ping(); err != nil {
				log.Printf("Database: %v\n", err)
			}
		}
	}()

	server := &http.Server{
		Addr:              sv.cfg.ListenAddress,
		IdleTimeout:       time.Second * 60,
		MaxHeaderBytes:    100 * 1000,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second * 120,
	}

	log.Fatalf("Server failed to start or crashed with error: %v",
		server.ListenAndServeTLS(sv.cfg.Certificate.File, sv.cfg.Certificate.Key),
	)
}
