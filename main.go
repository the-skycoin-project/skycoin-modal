/* // 2021 Moses Narrow //  */
/* // Skycoin Payment modal web app and api //  */
/* // custom payment gateway integration with snipcart.com of skycoin and btcpayserver //  */
package main
import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	slog "github.com/sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httputil"
	"encoding/json"
	"math"
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
	  qrcode "github.com/skip2/go-qrcode"
	)
func init() {
	if "LOCAL" == strings.ToUpper(os.Getenv("ENV")) {
		slog.SetFormatter(&slog.TextFormatter{})
		slog.SetLevel(slog.DebugLevel)} else {
		slog.SetFormatter(&slog.JSONFormatter{})
		slog.SetLevel(slog.InfoLevel)}}
func main() {
	var (		// Load environment variables
		env     = strings.ToUpper(os.Getenv("ENV")) // LOCAL, DEV, STG, PRD
		port    = os.Getenv("PORT")                 // server traffic on this port
		version = os.Getenv("VERSION")              // path to VERSION file
	)
	version, err := ParseVersionFile(version)	// Read version information
	if err != nil {	slog.WithFields(slog.Fields{"env":env,"err":err,"path":os.Getenv("VERSION"),}).Fatal("Can't find a VERSION file")
	return}
	slog.WithFields(slog.Fields{"env":env,"path":os.Getenv("VERSION"),"version": version,}).Info("Loaded VERSION file")
	//userStore := passport.NewUserService(passport.CreateMockDataSet())	// Initialise data storage
	appEnv := AppEnv{Render:render.New(),Version:version,Env:env,Port:port,}	//UserStore: userStore,}	// Initialise application context
	StartServer(appEnv)	// Start application
}
// AppEnv holds application configuration data
type AppEnv struct {
	Render    *render.Render
	Version   string
	Env       string
	Port      string
}//UserStore UserStorage
// CreateContextForTestSetup initialises an application context struct	// for testing purposes
func CreateContextForTestSetup() AppEnv {
	testVersion := "0.0.0"
	appEnv := AppEnv{Render:render.New(),Version:testVersion,Env:"LOCAL",Port:"8041",}	//UserStore: NewUserService(CreateMockDataSet()),
	return appEnv
}
// StartServer Wraps the mux Router and uses the Negroni Middleware
func StartServer(appEnv AppEnv) {
	statikFS, err := fs.New()
	if err != nil {log.Fatal(err)}
	router := mux.NewRouter().StrictSlash(true).SkipClean(true).UseEncodedPath()
	for _, route := range routes {
		var handler http.Handler
		handler = MakeHandler(appEnv, route.HandlerFunc)
		router.Methods(route.Method).Path(route.Pattern).Name(route.Name).Handler(handler)
	}
	router.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(statikFS)))
	// security
	var isDevelopment = false
	if appEnv.Env == "LOCAL" {isDevelopment = true}
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
	if appEnv.Env == "LOCAL" {n.Run("localhost:" + appEnv.Port)} else {n.Run(":" + appEnv.Port)}
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
	Route{"PaymentMethods", "POST", "/paywithskycoin", PaymentMethodsURL},	//return payment methods
	Route{"ModalTest", "GET", "/paywithskycoin", ModalTestURL},	//test view of payment modal
	Route{"ModalTest", "GET", "/paywithness", NessModalTestURL},	//test view of payment modal
	Route{"Payment", "GET", "/paywithskycoin/payment", PaymentURL},	//payment modal or request page
	Route{"Payment", "POST", "/paywithskycoin/payment", PaymentURL},	//payment modal or request page
	Route{"Payment", "GET", "/paywithbitcoin", BTCPaymentURL},
	Route{"Payment", "POST", "/paywithbitcoin", BTCPaymentURL},
	Route{"Payment", "GET", "/paywithprivateness", NessPaymentURL},
	Route{"Payment", "POST", "/paywithprivateness", NessPaymentURL},
}
// HandlerFunc is a custom implementation of the http.HandlerFunc
type HandlerFunc func(http.ResponseWriter, *http.Request, AppEnv)
// MakeHandler allows us to pass an environment struct to our handlers, without resorting to global
// variables. It accepts an environment (Env) struct and our own handler function. It returns
// a function of the type http.HandlerFunc so can be passed on to the HandlerFunc in main.go.
func MakeHandler(appEnv AppEnv, fn func(http.ResponseWriter, *http.Request, AppEnv)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Clacks-Overhead", "GNU Terry Pratchett")		// Terry Pratchett tribute
		fn(w, r, appEnv)		// return function with AppEnv
	}
}
// HealthcheckHandler returns useful info about the app
func HealthcheckHandler(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	check := Check{AppName: "go-rest-api-template",	Version: appEnv.Version,}
	appEnv.Render.JSON(w, http.StatusOK, check)
}
// SNIPCART INTEGRATION // return payment methods //
func PaymentMethodsURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	fmt.Println(string("PaymentMethodsURL Func called"))
	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {fmt.Println(err)}
	fmt.Println(string(requestDump))
	decoder := json.NewDecoder(req.Body)
	var p PaymentMethods
	err = decoder.Decode(&p)
	if err != nil {response := Response{Status:  strconv.Itoa(http.StatusBadRequest),	Message: "malformed PaymentMethods request object",}
		slog.WithFields(slog.Fields{"env":    appEnv.Env, "status": http.StatusBadRequest,}).Error("malformed PaymentMethods request object")
		appEnv.Render.JSON(w, http.StatusBadRequest, response)
		return}
	fmt.Println(string("Request Publictoken: " + p.Publictoken))
	fmt.Println(string("Request validation...")) //request validation step	// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken="+ p.Publictoken))
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken="+ p.Publictoken)
	if err != nil {slog.Fatalln(err)}
	fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	// fill in the struct with the response
	pmr0 := make([]PaymentMethodsResponseStruct, 0)
	pmr1 := PaymentMethodsResponseStruct{}
	pmr1.ID = "skycoin_payment"
	pmr1.Name = "Skycoin"
	pmr1.Checkouturl = SkyCheckOutUrl //+ p.Publictoken //they actually append a new public token on their end to the URL provided
	pmr0 = append(pmr0, pmr1)
	pmr01, _ := json.Marshal(pmr1)
	fmt.Println(string(pmr01))
	pmr2 := PaymentMethodsResponseStruct{}
	pmr2.ID = "bitcoin_payment"
	pmr2.Name = "Bitcoin"
	pmr2.Checkouturl = BtcCheckOutUrl //+ p.Publictoken //they actually append a new public token on their end to the URL provided
	pmr0 = append(pmr0, pmr2)
	pmr02, _ := json.Marshal(pmr2)
	fmt.Println(string(pmr02))
	pmr3 := PaymentMethodsResponseStruct{}
	pmr3.ID = "privateness_payment"
	pmr3.Name = "Privateness"
	pmr3.Checkouturl = NessCheckOutUrl //+ p.Publictoken //they actually append a new public token on their end to the URL provided
	pmr0 = append(pmr0, pmr3)
	pmr03, _ := json.Marshal(pmr3)
	fmt.Println(string(pmr03))
	appEnv.Render.JSON(w, http.StatusOK, pmr0)
}
//time function embedded in the page
func monthDayYear() string { return time.Now().Format("Monday January 2, 2006 15:04:05") }
//test view of the payment modal
func ModalTestURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {	//same as paymentmethodsURL endpoint but handles GET
	wd, err := os.Getwd()
	if err != nil {log.Fatal(err)}
	var fm = template.FuncMap{"fdateMDY": monthDayYear,}
	pmtreq := PaymentRequest{}
	pmtreq.CryptoName = "Skycoin"
	pmtreq.Ticker = "SKY"
	pmtreq.Address = "2jBbGxZRGoQG1mqhPBnXnLTxK6oxsTf8os6" //hardcoding genesis address as example
	qrc, err := qrcode.Encode("skycoin:" + pmtreq.Address, qrcode.Medium, 512)
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)
	var pricequeryresponse PriceQuery
	resp1, err := http.Get("https://api.coinpaprika.com/v1/tickers/sky-skycoin?quotes=USD")
	if err != nil {slog.Fatalln(err)}
	body, err := ioutil.ReadAll(resp1.Body)	// Read the response body
	if err != nil {slog.Fatalln(err)}
	fmt.Println(string("coinpaprika response:"))
	fmt.Println(body)
	_ = json.Unmarshal([]byte(body), &pricequeryresponse)
	currentrate := 	pricequeryresponse.Quotes.Usd.Price
	fmt.Println(string("currect rate"))
	s := fmt.Sprintf("%.2f", currentrate)
	fmt.Println(string(s))
	pmtreq.UsdAmount = 100.00
	quoteinsky := pmtreq.UsdAmount / currentrate
	if currentrate < 10.0 { quoteinsky = math.Floor(quoteinsky*1000)/1000	} else {	quoteinsky = math.Floor(quoteinsky*10000)/10000	}	//adapt the precision to the current rate
	pmtreq.Amount = quoteinsky
	tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
	tpl1.ExecuteTemplate(w, "index.html", pmtreq)	//payment modal
}

func NessModalTestURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {	//same as paymentmethodsURL endpoint but handles GET
	wd, err := os.Getwd()
	if err != nil {log.Fatal(err)}
	var fm = template.FuncMap{"fdateMDY": monthDayYear,}
	pmtreq := PaymentRequest{}
	pmtreq.CryptoName = "Privateness"
	pmtreq.Ticker = "NESS"
	pmtreq.Address = "24GJTLPMoz61sV4J4qg1n14x5qqDwXqyJJy" //hardcoding genesis address as example
	qrc, err := qrcode.Encode("privateness:" + pmtreq.Address, qrcode.Medium, 512)
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)
	var pricequeryresponse PriceQuery
	resp1, err := http.Get("https://api.coinpaprika.com/v1/tickers/ness-privateness?quotes=USD")
	if err != nil {slog.Fatalln(err)}
	body, err := ioutil.ReadAll(resp1.Body)	// Read the response body
	if err != nil {slog.Fatalln(err)}
	fmt.Println(string("coinpaprika response:"))
	fmt.Println(body)
	_ = json.Unmarshal([]byte(body), &pricequeryresponse)
	currentrate := 	pricequeryresponse.Quotes.Usd.Price
	fmt.Println(string("currect rate"))
	s := fmt.Sprintf("%.2f", currentrate)
	fmt.Println(string(s))
	pmtreq.UsdAmount = 100.00
	quoteinsky := pmtreq.UsdAmount / currentrate
	if currentrate < 10.0 { quoteinsky = math.Floor(quoteinsky*1000)/1000	} else {	quoteinsky = math.Floor(quoteinsky*10000)/10000	}	//adapt the precision to the current rate
	pmtreq.Amount = quoteinsky
	tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
	tpl1.ExecuteTemplate(w, "index.html", pmtreq)	//payment modal
}
// payment request // expecting GET
func PaymentURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	slug := req.URL.RawQuery	//slug := mux.Vars(req)["slug"] //public token provided previously must be validated first
	fmt.Println(string("Request Publictoken"))
	fmt.Println(string(slug))
	fmt.Println(string("Request validation..."))	//request validation step	// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug))
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug)
	if err != nil {	slog.Fatalln(err)	}	//fmt.Println(string("request validation response:")
	fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	pmtsess := PaymentSession{}
	fmt.Println(string("Retrieving payment session..."))	//retrieve the payment session //https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#retrieve-a-payment-session
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug))
	resp1, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug)
	if err != nil {	slog.Fatalln(err)	}
	defer resp1.Body.Close()
	decoder := json.NewDecoder(resp1.Body)
	err = decoder.Decode(&pmtsess)
	if err != nil { slog.Fatalln(err)	}
	fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode)) //response status
	fmt.Println(string("PaymentSession ID: " + pmtsess.ID)) //print payyment session ID to terminal
	printamount := fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)
	fmt.Println(string("PaymentSession Amount: " + printamount))
	//fmt.Println(string(fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)))	//print amount
	var fm = template.FuncMap{"fdateMDY": monthDayYear,} //current time is displayed in the page
	var pricequeryresponse PriceQuery
	resp2, err := http.Get("https://api.coinpaprika.com/v1/tickers/sky-skycoin?quotes=USD")
	if err != nil {slog.Fatalln(err)}
	body, err := ioutil.ReadAll(resp2.Body)	// Read the response body
	if err != nil {slog.Fatalln(err)}
	//fmt.Println(string("coinpaprika response:"))
	//fmt.Println(string(body))
	_ = json.Unmarshal([]byte(body), &pricequeryresponse)
	currentrate := 	pricequeryresponse.Quotes.Usd.Price
	fmt.Println(string("currect rate"))
	s := fmt.Sprintf("%.2f", currentrate)
	fmt.Println(string(s))
	quoteinsky := pmtsess.Invoice.Amount / currentrate
	if currentrate < 10.0 {	quoteinsky = math.Floor(quoteinsky*1000)/1000	} else {	quoteinsky = math.Floor(quoteinsky*10000)/10000 }	//adapt precision to the current rate
	pmtreq := PaymentRequest{}
	pmtreq.CryptoName = "Skycoin"
	pmtreq.Ticker = "SKY"
	pmtreq.Amount = quoteinsky
	pmtreq.Address = nextSkyAddress()	//get next address
	qrc, err := qrcode.Encode("skycoin:" + pmtreq.Address, qrcode.Medium, 512)	//qr encode the address
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)
	pmtreq.UsdAmount = pmtsess.Invoice.Amount
	wd, err := os.Getwd()
	if err != nil {log.Fatal(err)}
	tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
	if req.Method != http.MethodGet {	//check for post as defined below and in the template
		fmt.Println(string("Submitting Payment"))	//replace this stuff with autodetection of payment
		txid := req.FormValue("txid")
		refund := req.FormValue("refund")
		if txid != "" {
			fmt.Println(string("txid:"))
			fmt.Println(string(txid))
			fmt.Println(string("refund address:"))
			fmt.Println(string(refund))
			//post request for payment	//fmt.Println(fmt.Sprintf(`curl --request POST --url https://payment.snipcart.com/api/private/custom-payment-gateway/payment --header 'Authorization: Bearer %s' --header 'content-type: application/json' --data '{"paymentSessionId": "%s", "state": "processed", "error": ""}'`, os.Getenv("APIKEY"), pmtsess.ID))
			url :=  "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
			postdata := fmt.Sprintf(`{"paymentSessionId": "%s", "state": "processed", "error": ""}`, pmtsess.ID)
			var jsonStr = []byte(postdata)
			req0, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
			req0.Header.Set("Authorization", "Bearer " + os.Getenv("APIKEY"))
			req0.Header.Set("Content-Type", "application/json")
			resp, err := myClient.Do(req0)
			if err != nil {slog.Fatalln(err)}
			defer resp.Body.Close()
			var redir PaymentConfirmation
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&redir)
			if err != nil {slog.Fatalln(err)}
			fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
			//fmt.Println(string(resp))
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {slog.Fatalln(err)}
			fmt.Println(string("submit payment response:"))
			fmt.Println(string(body))
			fmt.Println(string(redir.Returnurl))
			http.Redirect(w, req, redir.Returnurl, http.StatusSeeOther)
		}
		} else {tpl1.ExecuteTemplate(w, "index.html", pmtreq)}
}
// payment request // expecting GET
func BTCPaymentURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	slug := req.URL.RawQuery	//slug := mux.Vars(req)["slug"] //public token provided previously must be validated first
	fmt.Println(string("Request Publictoken"))
	fmt.Println(string(slug))
	fmt.Println(string("Request validation..."))	//request validation step	// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug))
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug)
	if err != nil {	slog.Fatalln(err)	}	//fmt.Println(string("request validation response:")
	fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	pmtsess := PaymentSession{}
	fmt.Println(string("Retrieving payment session..."))	//retrieve the payment session //https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#retrieve-a-payment-session
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug))
	resp1, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug)
	if err != nil {	slog.Fatalln(err)	}
	defer resp1.Body.Close()
	decoder := json.NewDecoder(resp1.Body)
	err = decoder.Decode(&pmtsess)
	if err != nil { slog.Fatalln(err)	}
	fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode)) //response status
	fmt.Println(string("PaymentSession ID: " + pmtsess.ID)) //print payyment session ID to terminal
	printamount := fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)
	fmt.Println(string("PaymentSession Amount: " + printamount))
	//fmt.Println(string(fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)))	//print amount
	var fm = template.FuncMap{"fdateMDY": monthDayYear,} //current time is displayed in the page
	pmtreq := PaymentRequest{}
	pmtreq.CryptoName = "Bitcoin"
	pmtreq.Ticker = "BTC"
	pmtreq.UsdAmount = pmtsess.Invoice.Amount
	wd, err := os.Getwd()
	if err != nil {log.Fatal(err)}
	tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
	if req.Method != http.MethodGet {	//check for post as defined below and in the template
		fmt.Println(string("BTC Payment"))	//replace this stuff with autodetection of payment
		refund := req.FormValue("refund")
		if refund != "" {
			fmt.Println(string("refund address:"))
			fmt.Println(string(refund))
		}
		submit := req.FormValue("submit")
		if submit != "" {
			fmt.Println(string("submit:"))
			fmt.Println(string(submit))
			url :=  "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
			postdata := fmt.Sprintf(`{"paymentSessionId": "%s", "state": "processed", "error": ""}`, pmtsess.ID)
			var jsonStr = []byte(postdata)
			req0, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
			req0.Header.Set("Authorization", "Bearer " + os.Getenv("APIKEY"))
			req0.Header.Set("Content-Type", "application/json")
			resp, err := myClient.Do(req0)
			if err != nil {slog.Fatalln(err)}
			defer resp.Body.Close()
			var redir PaymentConfirmation
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&redir)
			if err != nil {slog.Fatalln(err)}
			fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
			//fmt.Println(string(resp))
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {slog.Fatalln(err)}
			fmt.Println(string("submit payment response:"))
			fmt.Println(string(body))
			fmt.Println(string(redir.Returnurl))
			http.Redirect(w, req, redir.Returnurl, http.StatusSeeOther)
} else {tpl1.ExecuteTemplate(w, "index.html", pmtreq)}
} else {tpl1.ExecuteTemplate(w, "index.html", pmtreq)}

}
// payment request // expecting GET
func NessPaymentURL(w http.ResponseWriter, req *http.Request, appEnv AppEnv) {
	slug := req.URL.RawQuery	//slug := mux.Vars(req)["slug"] //public token provided previously must be validated first
	fmt.Println(string("Request Publictoken"))
	fmt.Println(string(slug))
	fmt.Println(string("Request validation..."))	//request validation step	// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug))
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?"+ slug)
	if err != nil {	slog.Fatalln(err)	}	//fmt.Println(string("request validation response:")
	fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	pmtsess := PaymentSession{}
	fmt.Println(string("Retrieving payment session..."))	//retrieve the payment session //https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#retrieve-a-payment-session
	fmt.Println(string("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug))
	resp1, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?"+ slug)
	if err != nil {	slog.Fatalln(err)	}
	defer resp1.Body.Close()
	decoder := json.NewDecoder(resp1.Body)
	err = decoder.Decode(&pmtsess)
	if err != nil { slog.Fatalln(err)	}
	fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode)) //response status
	fmt.Println(string("PaymentSession ID: " + pmtsess.ID)) //print payyment session ID to terminal
	printamount := fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)
	fmt.Println(string("PaymentSession Amount: " + printamount))
	//fmt.Println(string(fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)))	//print amount
	var fm = template.FuncMap{"fdateMDY": monthDayYear,} //current time is displayed in the page
	var pricequeryresponse PriceQuery
	resp2, err := http.Get("https://api.coinpaprika.com/v1/tickers/ness-privateness?quotes=USD")
	if err != nil {slog.Fatalln(err)}
	body, err := ioutil.ReadAll(resp2.Body)	// Read the response body
	if err != nil {slog.Fatalln(err)}
	//fmt.Println(string("coinpaprika response:"))
	//fmt.Println(string(body))
	_ = json.Unmarshal([]byte(body), &pricequeryresponse)
	currentrate := 	pricequeryresponse.Quotes.Usd.Price
	fmt.Println(string("currect rate"))
	s := fmt.Sprintf("%.2f", currentrate)
	fmt.Println(string(s))
	quoteinness := pmtsess.Invoice.Amount / currentrate
	if currentrate < 10.0 {	quoteinness = math.Floor(quoteinness*1000)/1000	} else {	quoteinness = math.Floor(quoteinness*10000)/10000 }	//adapt precision to the current rate
	pmtreq := PaymentRequest{}
	pmtreq.CryptoName = "Privateness"
	pmtreq.Ticker = "NESS"
	pmtreq.Amount = quoteinness
	pmtreq.Address = nextNessAddress()	//get next address
	qrc, err := qrcode.Encode("privateness:" + pmtreq.Address, qrcode.Medium, 512)	//qr encode the address
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)
	pmtreq.UsdAmount = pmtsess.Invoice.Amount
	wd, err := os.Getwd()
	if err != nil {log.Fatal(err)}
	tpl1 := template.Must(template.New("").Funcs(fm).ParseFiles(wd + "/public/index.html"))
	if req.Method != http.MethodGet {	//check for post as defined below and in the template
		fmt.Println(string("Submitting Payment"))	//replace this stuff with autodetection of payment
		txid := req.FormValue("txid")
		refund := req.FormValue("refund")
		if txid != "" {
			fmt.Println(string("txid:"))
			fmt.Println(string(txid))
			fmt.Println(string("refund address:"))
			fmt.Println(string(refund))
			//post request for payment	//fmt.Println(fmt.Sprintf(`curl --request POST --url https://payment.snipcart.com/api/private/custom-payment-gateway/payment --header 'Authorization: Bearer %s' --header 'content-type: application/json' --data '{"paymentSessionId": "%s", "state": "processed", "error": ""}'`, os.Getenv("APIKEY"), pmtsess.ID))
			url :=  "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
			postdata := fmt.Sprintf(`{"paymentSessionId": "%s", "state": "processed", "error": ""}`, pmtsess.ID)
			var jsonStr = []byte(postdata)
			req0, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
			req0.Header.Set("Authorization", "Bearer " + os.Getenv("APIKEY"))
			req0.Header.Set("Content-Type", "application/json")
			resp, err := myClient.Do(req0)
			if err != nil {slog.Fatalln(err)}
			defer resp.Body.Close()
			var redir PaymentConfirmation
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&redir)
			if err != nil {slog.Fatalln(err)}
			fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
			//fmt.Println(string(resp))
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {slog.Fatalln(err)}
			fmt.Println(string("submit payment response:"))
			fmt.Println(string(body))
			fmt.Println(string(redir.Returnurl))
			http.Redirect(w, req, redir.Returnurl, http.StatusSeeOther)
		}
		} else {tpl1.ExecuteTemplate(w, "index.html", pmtreq)}
}
//
var myClient = &http.Client{Timeout: 10 * time.Second}
//
func nextSkyAddress() string {
	fmt.Println(string("Checking for next available address"))
	file, _ := ioutil.ReadFile("sky-addresses.txt")
	notfound := "address not found"
	addresses := AddressList{}
	address := notfound //default to not found, overwrite address when found
	testaddress := notfound
	_ = json.Unmarshal([]byte(file), &addresses)
	for i := 0; i < len(addresses.Addresses); i++ {
		if address == notfound {
			var q Balance //the struct that maps to the response of the query
			testaddress = addresses.Addresses[i]
			fmt.Println(string("Checking Addresses..."))
			fmt.Println(string("http://127.0.0.1:8001/api/balance?addrs="+ testaddress))
			resp1, err := http.Get("http://127.0.0.1:8001/api/balance?addrs="+ testaddress)
			if err != nil {slog.Fatalln(err)}
			defer resp1.Body.Close()
			decoder := json.NewDecoder(resp1.Body)
			err = decoder.Decode(&q)
			if err != nil {slog.Fatalln(err)}
			fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode))
			fmt.Println(string("Address"))
			fmt.Println(string(testaddress))
			fmt.Println(string("Current Coins:"))
			fmt.Println(q.Confirmed.Coins)
			if q.Confirmed.Coins == 0 {
				fmt.Println(string("Address is empty, Using:"))
				fmt.Println(string(testaddress))
				address = testaddress
				return address
			}
		}
	}
return address
}

func nextNessAddress() string {
	fmt.Println(string("Checking for next available address"))
	file, _ := ioutil.ReadFile("ness-addresses.txt")
	notfound := "address not found"
	addresses := AddressList{}
	address := notfound //default to not found, overwrite address when found
	testaddress := notfound
	_ = json.Unmarshal([]byte(file), &addresses)
	for i := 0; i < len(addresses.Addresses); i++ {
		if address == notfound {
			var q Balance //the struct that maps to the response of the query
			testaddress = addresses.Addresses[i]
			fmt.Println(string("Checking Addresses..."))
			fmt.Println(string("http://127.0.0.1:8002/api/balance?addrs="+ testaddress))
			resp1, err := http.Get("http://127.0.0.1:8002/api/balance?addrs="+ testaddress)
			if err != nil {slog.Fatalln(err)}
			defer resp1.Body.Close()
			decoder := json.NewDecoder(resp1.Body)
			err = decoder.Decode(&q)
			if err != nil {slog.Fatalln(err)}
			fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode))
			fmt.Println(string("Address"))
			fmt.Println(string(testaddress))
			fmt.Println(string("Current Coins:"))
			fmt.Println(q.Confirmed.Coins)
			if q.Confirmed.Coins == 0 {
				fmt.Println(string("Address is empty, Using:"))
				fmt.Println(string(testaddress))
				address = testaddress
				return address
			}
		}
	}
return address
}

var AppUrl string = "https://pay.magnetosphere.net/paywithskycoin" // return payment methods
var SkyCheckOutUrl string = "https://pay.magnetosphere.net/paywithskycoin/payment"	// payment modal
var BtcCheckOutUrl string = "https://pay.magnetosphere.net/paywithbitcoin"	// payment modal
var NessCheckOutUrl string = "https://pay.magnetosphere.net/paywithprivateness"	// payment modal

	type PaymentMethods struct {	// bad name for this func
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
//https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?

type PaymentSession struct {
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
			Hasselectedplan          bool    `json:"hasSelectedPlan"`
		} `json:"items"`
		Plan interface{} `json:"plan"`
	} `json:"invoice"`
	State                   string `json:"state"`
	Availablepaymentmethods []struct {
		ID          string `json:"id"`
		Flow        string `json:"flow"`
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"name,omitempty"`
		Checkouturl string `json:"checkoutUrl,omitempty"`
	} `json:"availablePaymentMethods"`
	ID                              string `json:"id"`
	Paymentmethod                   string `json:"paymentMethod"`
	Paymentauthorizationredirecturl string `json:"paymentAuthorizationRedirectUrl"`
	Authorization                   struct {
		Flow                      string      `json:"flow"`
		Confirmationsynchronicity string      `json:"confirmationSynchronicity"`
		State                     string      `json:"state"`
		Statedescriptorcode       interface{} `json:"stateDescriptorCode"`
		Statedescriptor           interface{} `json:"stateDescriptor"`
		URL                       string      `json:"url"`
		Card                      interface{} `json:"card"`
	} `json:"authorization"`
	Customerid        interface{} `json:"customerId"`
	Customergatewayid interface{} `json:"customerGatewayId"`
}
//sent as post request to snipcart to rgister payment in dashboard
type Payment struct {	//func is not currently used
	Paymentsessionid string `json:"paymentSessionId"`
	State            string `json:"state"`
	Error            struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	} `json:"error"`
}
//usedfor redirect url
type PaymentConfirmation struct {	Returnurl string `json:"returnUrl"` }
type PaymentRequest struct {	// populates payment request
	CryptoName string
	Ticker string
	QRCode string
	Address string
	Amount float64
	UsdAmount float64
}
// https://github.com/skycoin/skycoin/tree/develop/cmd/skycoin-cli#list-wallet-addresses
type AddressList struct {	Addresses []string `json:"addresses"` }	// struct maps to the output of `skycoin-cli listAddresses [wallet]`
// https://explorer.skycoin.com/api/balance?addrs=SeDoYN6SNaTiAZFHwArnFwQmcyz7ZvJm17
type Balance struct {
	Confirmed struct {
		Coins int `json:"coins"`
		Hours int `json:"hours"`
	} `json:"confirmed"`
	Predicted struct {
		Coins int `json:"coins"`
		Hours int `json:"hours"`
	} `json:"predicted"`
	Addresses struct {
		SevenCpq7T3Pzzxvjtst8G7Uvs7Xh4Lem8Fbpd struct {
			Confirmed struct {
				Coins int `json:"coins"`
				Hours int `json:"hours"`
			} `json:"confirmed"`
			Predicted struct {
				Coins int `json:"coins"`
				Hours int `json:"hours"`
			} `json:"predicted"`
		} `json:"7cpQ7t3PZZXvjTst8G7Uvs7XH4LeM8fBPD"`
	} `json:"addresses"`
}
//responce to price query from coinpaprika
type PriceQuery struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Symbol            string    `json:"symbol"`
	Rank              int       `json:"rank"`
	CirculatingSupply int       `json:"circulating_supply"`
	TotalSupply       int       `json:"total_supply"`
	MaxSupply         int       `json:"max_supply"`
	BetaValue         float64   `json:"beta_value"`
	FirstDataAt       time.Time `json:"first_data_at"`
	LastUpdated       time.Time `json:"last_updated"`
	Quotes            struct {
		Usd struct {
			Price               float64   `json:"price"`
			Volume24H           float64   `json:"volume_24h"`
			Volume24HChange24H  float64   `json:"volume_24h_change_24h"`
			MarketCap           int       `json:"market_cap"`
			MarketCapChange24H  float64   `json:"market_cap_change_24h"`
			PercentChange15M    float64   `json:"percent_change_15m"`
			PercentChange30M    float64   `json:"percent_change_30m"`
			PercentChange1H     float64   `json:"percent_change_1h"`
			PercentChange6H     float64   `json:"percent_change_6h"`
			PercentChange12H    float64   `json:"percent_change_12h"`
			PercentChange24H    float64   `json:"percent_change_24h"`
			PercentChange7D     float64   `json:"percent_change_7d"`
			PercentChange30D    float64   `json:"percent_change_30d"`
			PercentChange1Y     float64   `json:"percent_change_1y"`
			AthPrice            float64   `json:"ath_price"`
			AthDate             time.Time `json:"ath_date"`
			PercentFromPriceAth float64   `json:"percent_from_price_ath"`
		} `json:"USD"`
	} `json:"quotes"`
}
// Below here is back to the unmodified code
// Check will store information about its name and version
type Check struct {
	AppName string `json:"appName"`
	Version string `json:"version"`
}
// GoString implements the GoStringer interface so we can display the full struct during debugging
// usage: fmt.Printf("%#v", i)	// ensure that i is a pointer, so might need to do &i in some cases
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
// 404: Not found	// 500: Internal Server Error
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	URL string `json:"url"`
}
// GoString implements the GoStringer interface so we can display the full struct during debugging
// usage: fmt.Printf("%#v", i)	// ensure that i is a pointer, so might need to do &i in some cases
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
	if err != nil {	return "", stacktrace.Propagate(err, "error reading version file")	}
	version := string(dat)
	version = strings.Trim(strings.Trim(version, "\n"), " ")
	// regex pulled from official https://github.com/sindresorhus/semver-regex
	semverRegex := `^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[\da-z\-]+(?:\.[\da-z\-]+)*)?(?:\+[\da-z\-]+(?:\.[\da-z\-]+)*)?$`
	match, err := regexp.MatchString(semverRegex, version)
	if err != nil {	return "", stacktrace.Propagate(err, "error executing regex match")	}
	if !match {	return "", stacktrace.NewError("string in VERSION is not a valid version number")	}
	return version, nil
}
