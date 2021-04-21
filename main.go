package main

import (
//	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	slog "github.com/sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httputil"
	"encoding/json"
	"github.com/urfave/negroni"
	"os"
	"regexp"
	"github.com/unrolled/render"
	"github.com/unrolled/secure"
	"github.com/palantir/stacktrace"
	"strconv"
	"strings"
	"html/template"
	"time"
	_ "github.com/the-skycoin-project/skycoin-modal/statik"
	"github.com/rakyll/statik/fs"
	)

func init() {
	if "LOCAL" == strings.ToUpper(os.Getenv("ENV")) {
		slog.SetFormatter(&slog.TextFormatter{})
		slog.SetLevel(slog.DebugLevel)
	} else {
		slog.SetFormatter(&slog.JSONFormatter{})
		slog.SetLevel(slog.InfoLevel)
	}
}

func main() {
	// ===========================================================================
	// Load environment variables
	// ===========================================================================
	var (
		env     = strings.ToUpper(os.Getenv("ENV")) // LOCAL, DEV, STG, PRD
		port    = os.Getenv("PORT")                 // server traffic on this port
		version = os.Getenv("VERSION")              // path to VERSION file
	)
	// ===========================================================================
	// Read version information
	// ===========================================================================
	version, err := ParseVersionFile(version)
	if err != nil {
		slog.WithFields(slog.Fields{
			"env":  env,
			"err":  err,
			"path": os.Getenv("VERSION"),
		}).Fatal("Can't find a VERSION file")
		return
	}
	slog.WithFields(slog.Fields{
		"env":     env,
		"path":    os.Getenv("VERSION"),
		"version": version,
	}).Info("Loaded VERSION file")
	// ===========================================================================
	// Initialise data storage
	// ===========================================================================
	//userStore := passport.NewUserService(passport.CreateMockDataSet())
	// ===========================================================================
	// Initialise application context
	// ===========================================================================
	appEnv := AppEnv{
		Render:    render.New(),
		Version:   version,
		Env:       env,
		Port:      port,
		//UserStore: userStore,
	}
	// ===========================================================================
	// Start application
	// ===========================================================================
	StartServer(appEnv)
}

// AppEnv holds application configuration data
type AppEnv struct {
	Render    *render.Render
	Version   string
	Env       string
	Port      string
	//UserStore UserStorage
}

// CreateContextForTestSetup initialises an application context struct
// for testing purposes
func CreateContextForTestSetup() AppEnv {
	testVersion := "0.0.0"
	appEnv := AppEnv{
		Render:    render.New(),
		Version:   testVersion,
		Env:       "LOCAL",
		Port:      "8041",
		//UserStore: NewUserService(CreateMockDataSet()),
	}
	return appEnv
}

// StartServer Wraps the mux Router and uses the Negroni Middleware
func StartServer(appEnv AppEnv) {
	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler http.Handler
		handler = MakeHandler(appEnv, route.HandlerFunc)
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}
	router.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(statikFS)))

	// security
	var isDevelopment = false
	if appEnv.Env == "LOCAL" {
		isDevelopment = true
	}
	secureMiddleware := secure.New(secure.Options{
		// This will cause the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains
		// options to be ignored during development. When deploying to production,
		// be sure to set this to false.
		IsDevelopment: isDevelopment,
		// AllowedHosts is a list of fully qualified domain names that are allowed (CORS)
		AllowedHosts: []string{},
		// If ContentTypeNosniff is true, adds the X-Content-Type-Options header
		// with the value `nosniff`. Default is false.
		ContentTypeNosniff: true,
		// If BrowserXssFilter is true, adds the X-XSS-Protection header with the
		// value `1; mode=block`. Default is false.
		BrowserXssFilter: true,
	})
	// start now
	n := negroni.New()
	n.Use(negroni.NewLogger())
	n.Use(negroni.HandlerFunc(secureMiddleware.HandlerFuncWithNext))
	n.UseHandler(router)
	startupMessage := "===> Starting app (v" + appEnv.Version + ")"
	startupMessage = startupMessage + " on http://127.0.0.1:" + appEnv.Port
	startupMessage = startupMessage + " in " + appEnv.Env + " mode."
	log.Println(startupMessage)
	if appEnv.Env == "LOCAL" {
		n.Run("localhost:" + appEnv.Port)
	} else {
		n.Run(":" + appEnv.Port)
	}
}


// Route is the model for the router setup
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc HandlerFunc
}

// Routes are the main setup for our Router
type Routes []Route

var routes = Routes{
	Route{"Healthcheck", "GET", "/healthcheck", HealthcheckHandler},
	/*//=== Define the routes expected by snipcart === //*/
	/*// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference //*/
	/*// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#payment-methods //*/
	Route{"PaymentMethods", "POST", "/paywithskycoin", PaymentMethodsURL},	//return payment methods
	Route{"ModalTest", "GET", "/paywithskycoin", ModalTestURL},	//test view of payment modal
	Route{"Payment", "GET", "/paywithskycoin/payment/{slug}", PaymentURL},	//payment modal or request page
	/*
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/healthcheck", HealthcheckHandler).Methods("GET")
	r.HandleFunc("/paywithskycoin", PaymentMethodsURL).Methods("POST") //return payment methods
	r.HandleFunc("/paywithskycoin", ModalTestURL).Methods("GET") //test view of payment modal
	r.HandleFunc("/paywithskycoin/payment/{slug}", PaymentURL).Methods("GET") //payment modal or request page
	//Route{"SubmitPayment", "POST", "/paywithskycoin/payment/{slug}/confirm", SubmitPaymentURL}, //post request here with the txid
	//r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	*/

}

// HandlerFunc is a custom implementation of the http.HandlerFunc
type HandlerFunc func(http.ResponseWriter, *http.Request, AppEnv)
// MakeHandler allows us to pass an environment struct to our handlers, without resorting to global
// variables. It accepts an environment (Env) struct and our own handler function. It returns
// a function of the type http.HandlerFunc so can be passed on to the HandlerFunc in main.go.
func MakeHandler(appEnv AppEnv, fn func(http.ResponseWriter, *http.Request, AppEnv)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Terry Pratchett tribute
		w.Header().Set("X-Clacks-Overhead", "GNU Terry Pratchett")
		// return function with AppEnv
		fn(w, r, appEnv)
	}
}

// HealthcheckHandler returns useful info about the app
func HealthcheckHandler(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	check := Check{
		AppName: "go-rest-api-template",
		Version: appEnv.Version,
	}
	appEnv.Render.JSON(w, http.StatusOK, check)
}

// return payment methods
func PaymentMethodsURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	requestDump, err := httputil.DumpRequest(req, true)
if err != nil {
  fmt.Println(err)
}
fmt.Println(string(requestDump))
	decoder := json.NewDecoder(req.Body)
	var p PaymentMethods
	err = decoder.Decode(&p)
	if err != nil {
		response := Response{
			Status:  strconv.Itoa(http.StatusBadRequest),
			Message: "malformed PaymentMethods request object",
		}
		slog.WithFields(slog.Fields{
			"env":    appEnv.Env,
			"status": http.StatusBadRequest,
		}).Error("malformed PaymentMethods request object")
		appEnv.Render.JSON(w, http.StatusBadRequest, response)
		return
	}
	fmt.Println(string("response Publictoken: %s" + p.Publictoken))

//request validation step
// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken="+ p.Publictoken)
	if err != nil {
		 slog.Fatalln(err)
	}
//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		 slog.Fatalln(err)
} //should do something with body, at least print to screen
fmt.Println(string(body))
// fill in the struct with the response
pmr1 := make([]PaymentMethodsResponseStruct, 0)
pmr := PaymentMethodsResponseStruct{}
pmr.ID = "skycoin_payment"
pmr.Name = "Skycoin"
pmr.Checkouturl = CheckOutUrl //  + p.Publictoken,
pmr1 = append(pmr1, pmr)
pmr2, _ := json.Marshal(pmr)
	fmt.Println(string(pmr2))

	appEnv.Render.JSON(w, http.StatusOK, pmr1)
}



//time function embedded in the page
func monthDayYear() string {
	return time.Now().Format("Monday January 2, 2006 15:04:05")
}

//same as paymentmethodsURL endpoint but handles GET
func ModalTestURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
wd, err := os.Getwd()
if err != nil {
	 log.Fatal(err)
}
var fm = template.FuncMap{
	"fdateMDY": monthDayYear,
}
pmr := PaymentRequest{}
pmr.Address = "2jBbGxZRGoQG1mqhPBnXnLTxK6oxsTf8os6" //hardcoding genesis address as example
pmr.Amount = 100
//payment modal
tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
tpl1.ExecuteTemplate(w, "index.html", pmr)

/*
url :=  "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
var jsonStr = []byte(`{"paymentSessionId:" pmtid, "state:" "processed", "error:" {"code:" "", "message:" ""} }`)
req, err = http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
  req.Header.Set("Authorization", "Bearer <YOUR_SECRET_API_KEY>")
	req.Header.Set("Content-Type", "application/json")
	//resp, err = http.Get("")
	if err != nil {
		 slog.Fatalln(err)
	}
//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		 slog.Fatalln(err)
}
*/
}

// here is the payment request
func PaymentURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	slug := mux.Vars(req)["slug"] //public token provided previously must be validated first
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken="+ slug )
	if err != nil {
		 slog.Fatalln(err)
	}
//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		 slog.Fatalln(err)
}
fmt.Println(body)

//retrieve the payment session
pmtsess := PaymentSession{}
getJson("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?publicToken="+ slug, &pmtsess)
pmtid := pmtsess.ID
fmt.Println(pmtid)

wd, err := os.Getwd()
if err != nil {
	 log.Fatal(err)
}
var fm = template.FuncMap{
	"fdateMDY": monthDayYear,
}
//req.ParseForm()
//        fmt.Println("txid:", req.Form["txid"])
pmr := PaymentRequest{}
pmr.Address = "2jBbGxZRGoQG1mqhPBnXnLTxK6oxsTf8os6" //hardcoding genesis address as example
pmr.Amount = pmtsess.Invoice.Amount
//payment modal
tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
tpl1.ExecuteTemplate(w, "index.html", pmr)

/*
url :=  "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
var jsonStr = []byte(`{"paymentSessionId:" pmtid, "state:" "processed", "error:" {"code:" "", "message:" ""} }`)
req, err = http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
  req.Header.Set("Authorization", "Bearer <YOUR_SECRET_API_KEY>")
	req.Header.Set("Content-Type", "application/json")
	//resp, err = http.Get("")
	if err != nil {
		 slog.Fatalln(err)
	}
//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		 slog.Fatalln(err)
}
*/
}
var myClient = &http.Client{Timeout: 10 * time.Second}
func getJson(url string, target interface{}) error {
    r, err := myClient.Get(url)
    if err != nil {
        return err
    }
    defer r.Body.Close()

    return json.NewDecoder(r.Body).Decode(target)
}

/*	//to do
func SubmitPaymentURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {

	url := "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
	pmt := Payment{}
	pmt.Paymentsessionid = txid
	State            string `json:"state"`
	Error            struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		} `json:"error"`
	}
	var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	//req.Header.Set("Authorization" "Bearer <YOUR_SECRET_API_KEY>")
	req.Header.Set("Authorization", "Bearer <YOUR_SECRET_API_KEY>")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.Get("")
	if err != nil {
		slog.Fatalln(err)
	}
	//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		slog.Fatalln(err)
	}


}
*/

var AppUrl string = "https://magnetosphere.net/paywithskycoin/" // return payment methods
var CheckOutUrl string = "https://magnetosphere.net/paywithskycoin/payment/"	// payment modal
//var PaymentUrl string = "https://magnetosphere.net/paywithskycoin/payment/confirm"	// post req here with txid

	type PaymentMethods struct {
			Invoice struct {
				Shippingaddress struct {
					Name            string      `json:"name"`
					Streetandnumber string      `json:"streetAndNumber"`
					Postalcode      string      `json:"postalCode"`
					Country         string      `json:"country"`
					City            string      `json:"city"`
					Surname         interface{} `json:"surname"`
					Region          interface{} `json:"region"`
				} `json:"shippingAddress"`
				Billingaddress struct {
					Name            string      `json:"name"`
					Streetandnumber string      `json:"streetAndNumber"`
					Postalcode      string      `json:"postalCode"`
					Country         string      `json:"country"`
					City            string      `json:"city"`
					Surname         interface{} `json:"surname"`
					Region          interface{} `json:"region"`
				} `json:"billingAddress"`
				Email    string  `json:"email"`
				Language string  `json:"language"`
				Currency string  `json:"currency"`
				Amount   float64 `json:"amount"`
				Targetid string  `json:"targetId"`
				Items    []struct {
					Name                     string  `json:"name"`
					Unitprice                float64 `json:"unitPrice"`
					Quantity                 int     `json:"quantity"`
					Type                     string  `json:"type"`
					Discountamount           float64 `json:"discountAmount"`
					Rateoftaxincludedinprice float64 `json:"rateOfTaxIncludedInPrice"`
					Amount                   float64 `json:"amount"`
				} `json:"items"`
			} `json:"invoice"`
			Publictoken string `json:"publicToken"`
			Mode        string `json:"mode"`
		}

// the initial request from snipcart
type PaymentMethodsResponse struct {
	PMR []PaymentMethodsResponseStruct
}
	type PaymentMethodsResponseStruct struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Checkouturl string `json:"checkoutUrl"`
	Iconurl     string `json:"iconUrl,omitempty"`
}

	type PaymentSession struct {
	Invoice struct {
		Shippingaddress struct {
			Name            string      `json:"name"`
			Streetandnumber string      `json:"streetAndNumber"`
			Postalcode      string      `json:"postalCode"`
			Country         string      `json:"country"`
			City            string      `json:"city"`
			Region          interface{} `json:"region"`
		} `json:"shippingAddress"`
		Billingaddress struct {
			Name            string      `json:"name"`
			Streetandnumber string      `json:"streetAndNumber"`
			Postalcode      string      `json:"postalCode"`
			Country         string      `json:"country"`
			City            string      `json:"city"`
			Region          interface{} `json:"region"`
		} `json:"billingAddress"`
		Email    string  `json:"email"`
		Language string  `json:"language"`
		Currency string  `json:"currency"`
		Amount   float64 `json:"amount"`
		Targetid string  `json:"targetId"`
		Items    []struct {
			Name                     string  `json:"name"`
			Unitprice                float64 `json:"unitPrice"`
			Quantity                 int     `json:"quantity"`
			Type                     string  `json:"type"`
			Rateoftaxincludedinprice int     `json:"rateOfTaxIncludedInPrice"`
			Amount                   float64 `json:"amount"`
		} `json:"items"`
	} `json:"invoice"`
	ID                              string `json:"id"`
	Paymentauthorizationredirecturl string `json:"paymentAuthorizationRedirectUrl"`
}


//sent as post request to snipcart to rgister payment in dashboard
type Payment struct {
	Paymentsessionid string `json:"paymentSessionId"`
	State            string `json:"state"`
	Error            struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	} `json:"error"`
}

type PaymentRequest struct {
	QRCode string
	Address string
	Amount float64
}

// Check will store information about its name and version
type Check struct {
	AppName string `json:"appName"`
	Version string `json:"version"`
}

// GoString implements the GoStringer interface so we can display the full struct during debugging
// usage: fmt.Printf("%#v", i)
// ensure that i is a pointer, so might need to do &i in some cases
func (c *Check) GoString() string {
	return fmt.Sprintf(`
{
	AppName: %s,
	Version: %s,
}`,
		c.AppName,
		c.Version,
	)
}

// Response is a custom response object we pass around the system and send back to the customer
// 404: Not found
// 500: Internal Server Error
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// GoString implements the GoStringer interface so we can display the full struct during debugging
// usage: fmt.Printf("%#v", i)
// ensure that i is a pointer, so might need to do &i in some cases
func (r *Response) GoString() string {
	return fmt.Sprintf(`
{
	Status: %s,
	Message: %s,
}`,
		r.Status,
		r.Message,
	)
}


// ParseVersionFile returns the version as a string, parsing and validating a file given the path
func ParseVersionFile(versionPath string) (string, error) {
	dat, err := ioutil.ReadFile(versionPath)
	if err != nil {
		return "", stacktrace.Propagate(err, "error reading version file")
	}
	version := string(dat)
	version = strings.Trim(strings.Trim(version, "\n"), " ")
	// regex pulled from official https://github.com/sindresorhus/semver-regex
	semverRegex := `^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[\da-z\-]+(?:\.[\da-z\-]+)*)?(?:\+[\da-z\-]+(?:\.[\da-z\-]+)*)?$`
	match, err := regexp.MatchString(semverRegex, version)
	if err != nil {
		return "", stacktrace.Propagate(err, "error executing regex match")
	}
	if !match {
		return "", stacktrace.NewError("string in VERSION is not a valid version number")
	}
	return version, nil
}
