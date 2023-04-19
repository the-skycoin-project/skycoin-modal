package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
"strconv"
"sync"
 "fmt"
 "github.com/bitfield/script"
 "github.com/gin-gonic/gin"
 "github.com/spf13/cobra"
 "log"
 "net/http"
 "os"
 "time"
 "math"
 qrcode "github.com/skip2/go-qrcode"

)

func main() {
 Execute()
}

func init() {
 RootCmd.CompletionOptions.DisableDefaultCmd = true
 RootCmd.AddCommand( RunCmd, )
}

var RootCmd = & cobra.Command{ Use:   "g8", Short: "payment gateway (re)implementation",}

// Execute executes root CLI command.
func Execute() { if err := RootCmd.Execute(); err != nil { log.Fatal("Failed to execute command: ", err) }}

var webPort int
func init() {	RunCmd.Flags().IntVarP(&webPort, "port", "p", 8044, "port to serve on") }

var RunCmd = &cobra.Command{ Use:   "run", Short: "run the payment gateway", Run: func(_ *cobra.Command, _ []string) {	 Server() },}

func Server() {
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		r := newRouter()
		fmt.Printf("listening on http://127.0.0.1:%d using gin router\n", webPort)
		r.Run(fmt.Sprintf(":%d", webPort))
		wg.Done()
	}()
	wg.Wait()
	return
}

func newRouter() *gin.Engine {
	r := gin.Default()
//	gin.SetMode(gin.ReleaseMode)
	r.SetTrustedProxies(nil)
	r.NoRoute(func(c *gin.Context) {	//404
	c.Writer.WriteHeader(http.StatusNotFound)
	})
	r.GET("/", func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusNotFound)
	})
	r.POST("/paywithskycoin", PaymentMethodsURL)
//	r.GET("/paywithskycoin", ModalTestURL)
	r.GET("/paywithskycoin/payment", PaymentURL)
	r.POST("/paywithskycoin/payment", PaymentURL)
	r.GET("/paywithbitcoin", BTCPaymentURL)
	r.POST("/paywithbitcoin", BTCPaymentURL)

//	faviconBuffer, _ := base64.StdEncoding.DecodeString(faviconBase64)
//	r.GET("/favicon.ico", func(c *gin.Context) {		_, _ = c.Writer.WriteString(string(faviconBuffer))	})
return r
}

func PaymentMethodsURL(c *gin.Context) {
	fmt.Println("PaymentMethodsURL Func called")
	var p PaymentMethods
	if err := c.BindJSON(&p); err != nil {
		response := Response{Status: strconv.Itoa(http.StatusBadRequest), Message: "malformed PaymentMethods request object"}
		c.JSON(http.StatusBadRequest, response)
		return
	}
	fmt.Println("Request Publictoken: " + p.Publictoken)
	fmt.Println("Request validation...") //request validation step	// https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
	fmt.Println("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken=" + p.Publictoken)
	resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?publicToken=" + p.Publictoken)
	if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
  }
	fmt.Printf("HTTP Response Status:\n%d\n%s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
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

	c.JSON(http.StatusOK, pmr0)
	return
}


// payment request // expecting GET
// PaymentURL handles a GET request for a payment URL
func PaymentURL(c *gin.Context) {
  slug := c.Request.URL.RawQuery // slug := c.Param("slug") // public token provided previously must be validated first
  fmt.Println("Request Publictoken")
  fmt.Println(slug)
  fmt.Println("Request validation...") // request validation step // https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#request
  fmt.Println("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?" + slug)
  resp, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?" + slug)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
  }
  defer resp.Body.Close()
	fmt.Printf("HTTP Response Status:\n%d\n%s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
  pmtsess := PaymentSession{}
  fmt.Println("Retrieving payment session...") // retrieve the payment session //https://docs.snipcart.com/v3/custom-payment-gateway/technical-reference#retrieve-a-payment-session
  fmt.Println("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?" + slug)
  resp1, err := http.Get("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?" + slug)
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  defer resp1.Body.Close()
  decoder := json.NewDecoder(resp1.Body)
  err = decoder.Decode(&pmtsess)
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  fmt.Println("HTTP Response Status:", resp1.StatusCode, http.StatusText(resp1.StatusCode)) // response status
  fmt.Println("PaymentSession ID: " + pmtsess.ID)                                              // print payment session ID to terminal
  printamount := fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)
  fmt.Println("PaymentSession Amount: " + printamount)
  var pricequeryresponse PriceQuery
  resp2, err := http.Get("https://api.coinpaprika.com/v1/tickers/sky-skycoin?quotes=USD")
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  body, err := io.ReadAll(resp2.Body) // Read the response body
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  _ = json.Unmarshal([]byte(body), &pricequeryresponse)
  currentrate := pricequeryresponse.Quotes.Usd.Price
  fmt.Println("currect rate")
  s := fmt.Sprintf("%.2f", currentrate)
  fmt.Println(s)
  quoteinsky := pmtsess.Invoice.Amount / currentrate
  if currentrate < 10.0 {
      quoteinsky = math.Floor(quoteinsky*1000) / 1000
  } else {
      quoteinsky = math.Floor(quoteinsky*10000) / 10000
  }
  pmtreq := PaymentRequest{}
	pmtreq.Amount = pmtsess.Invoice.Amount
	fmt.Println("PaymentRequest:", pmtreq)
	reqaddress := nextSkyAddress()
	qrc, err := qrcode.Encode("skycoin:" + reqaddress, qrcode.Medium, 512)
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)
	htmltowrite := `<!DOCTYPE html>
<html lang="en">
<head>
<title>Pay with Skycoin</title>
</head>
<body>
<center>
<div>
<h1>Skycoin</h1>
<img class='media-object dp' src='data:image/png;base64,`+pmtreq.QRCode+`' style='width: 256px;height:256px;'>
<br>
<p>Payment Address:</p>
<h4>`+reqaddress+`</h4>
USD Amount: $`+fmt.Sprintf("%f",pmtsess.Invoice.Amount)+`</p>
<p>SKY Amount: `+fmt.Sprintf("%f",quoteinsky)+`</p>
<p>please specify a refund address and the transaction ID</p>
<form method="POST">
<label>Transaction ID:</label>
<textarea name="txid"></textarea><br>
<label>refund address:</label>
<textarea name="refund"></textarea><br>
<input type="submit" value="submit payment">
</form>
</div>
</center>
</body>
</html>
`
	fmt.Printf("Refund address: %s\n",c.PostForm("refund"))
	fmt.Printf("TXID: %s\n",c.PostForm("txid"))

	if c.Request.Method == http.MethodPost {
		fmt.Println("Submitting Payment")
		txid := c.PostForm("txid")
		refund := c.PostForm("refund")
		if txid == "" {
			c.String(http.StatusBadRequest, "Missing txid parameter")
			return
		}
		fmt.Println("txid:", txid)
		fmt.Println("refund address:", refund)
		url := "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
		postdata := fmt.Sprintf(`{"paymentSessionId": "%s", "state": "processed", "error": ""}`, pmtsess.ID)
		req, err := http.NewRequest("POST", url, bytes.NewBufferString(postdata))
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request: %v", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv("APIKEY"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := myClient.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error sending request: %v", err)
			return
		}
		defer resp.Body.Close()
		var redir PaymentConfirmation
		err = json.NewDecoder(resp.Body).Decode(&redir)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error decoding response: %v", err)
			return
		}
		fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
		fmt.Println("submit payment response:", redir.Returnurl)
		c.Redirect(http.StatusSeeOther, redir.Returnurl)
		return
}
if c.Request.Method == http.MethodGet {
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Write([]byte(htmltowrite))
	return
}
return
}


// payment request // expecting GET
func BTCPaymentURL(c *gin.Context) {
	fmt.Println("BTCPaymentURL")
	slug := c.Request.URL.RawQuery

	fmt.Printf("Request validation...")
	req := fmt.Sprintf("https://payment.snipcart.com/api/public/custom-payment-gateway/validate?%s", slug)
	fmt.Printf(req+"\n")
	resp, err := http.Get(req)
	if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
  }
	fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	pmtsess := PaymentSession{}
	fmt.Printf("Retrieving payment session...")
	req = fmt.Sprintf("https://payment.snipcart.com/api/public/custom-payment-gateway/payment-session?%s", slug)
	fmt.Printf(req+"\n")
	resp1, err := http.Get(req)
	if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
  }
	defer resp1.Body.Close()
	decoder := json.NewDecoder(resp1.Body)
	err = decoder.Decode(&pmtsess)
	if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
  }
	fmt.Printf("HTTP Response Status:\n%d\n%s\n", resp1.StatusCode, http.StatusText(resp1.StatusCode))
	fmt.Printf("PaymentSession ID: %s\n", pmtsess.ID)
	printamount := fmt.Sprintf("$%.2f", pmtsess.Invoice.Amount)
  fmt.Println("PaymentSession Amount: " + printamount)
  var pricequeryresponse PriceQuery
  resp2, err := http.Get("https://api.coinpaprika.com/v1/tickers/btc-bitcoin?quotes=USD")
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  body, err := io.ReadAll(resp2.Body) // Read the response body
  if err != nil {
      c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      return
  }
  _ = json.Unmarshal([]byte(body), &pricequeryresponse)
  currentrate := pricequeryresponse.Quotes.Usd.Price
  fmt.Println("currect rate")
  s := fmt.Sprintf("%.2f", currentrate)
  fmt.Println(s)
  quoteinbtc := pmtsess.Invoice.Amount / currentrate
  if currentrate < 10.0 {
      quoteinbtc = math.Floor(quoteinbtc*1000) / 1000
  } else {
      quoteinbtc = math.Floor(quoteinbtc*10000) / 10000
  }

	addr, _ := script.Exec(`bash -c 'electrum -w=/home/d0mo/.electrum/wallets/watch_wallet getunusedaddress'`).String()
	qrc, err := qrcode.Encode("bitcoin:" + addr, qrcode.Medium, 512)
	if err != nil {fmt.Printf("could not generate QRCode: %v", err)}
//	pmtreq.QRCode = base64.StdEncoding.EncodeToString(qrc)

	htmltowrite := `<!DOCTYPE html>
<html lang="en">
<head>
<title>Pay with Bitcoin</title>
</head>
<body>
<center>
<div>
<h1>Bitcoin</h1>
<img class='media-object dp' src='data:image/png;base64,`+base64.StdEncoding.EncodeToString(qrc)+`' style='width: 256px;height:256px;'>
<br>
<p>Payment Address:</p>
<h4>`+addr+`</h4>
USD Amount: $`+fmt.Sprintf("%f",pmtsess.Invoice.Amount)+`</p>
<p>BTC Amount: `+fmt.Sprintf("%f",quoteinbtc)+`</p>
<p>please specify a refund address and the transaction ID</p>
<form method="POST">
<label>Transaction ID:</label>
<textarea name="txid"></textarea><br>
<label>refund address:</label>
<textarea name="refund"></textarea><br>
<input type="submit" value="submit payment">
</form>
</div>
</center>
</body>
</html>
`
	fmt.Printf("Refund address: %s\n",c.PostForm("refund"))
	fmt.Printf("TXID: %s\n",c.PostForm("txid"))

	if c.Request.Method == http.MethodPost {
		fmt.Println("Submitting Payment")
		txid := c.PostForm("txid")
		refund := c.PostForm("refund")
		if txid == "" {
			c.String(http.StatusBadRequest, "Missing txid parameter")
			return
		}
		fmt.Println("txid:", txid)
		fmt.Println("refund address:", refund)
		url := "https://payment.snipcart.com/api/private/custom-payment-gateway/payment"
		postdata := fmt.Sprintf(`{"paymentSessionId": "%s", "state": "processed", "error": ""}`, pmtsess.ID)
		req, err := http.NewRequest("POST", url, bytes.NewBufferString(postdata))
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request: %v", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv("APIKEY"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := myClient.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error sending request: %v", err)
			return
		}
		defer resp.Body.Close()
		var redir PaymentConfirmation
		err = json.NewDecoder(resp.Body).Decode(&redir)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error decoding response: %v", err)
			return
		}
		fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
		fmt.Println("submit payment response:", redir.Returnurl)
		c.Redirect(http.StatusSeeOther, redir.Returnurl)
		return
}
if c.Request.Method == http.MethodGet {
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Write([]byte(htmltowrite))
	return
}
return
}
//
var myClient = &http.Client{Timeout: 10 * time.Second}
//

func nextSkyAddress() string {
	fmt.Printf("Checking for next available address")
	file, _ := os.ReadFile("sky-addresses.txt")
	notfound := "address not found"
	addresses := AddressList{}
	address := notfound //default to not found, overwrite address when found
	testaddress := notfound
	_ = json.Unmarshal([]byte(file), &addresses)
	for i := 0; i < len(addresses.Addresses); i++ {
		if address == notfound {
			var q Balance //the struct that maps to the response of the query
			testaddress = addresses.Addresses[i]
			fmt.Printf("Checking Addresses...")
			fmt.Printf("http://127.0.0.1:8001/api/balance?addrs="+ testaddress)
			resp1, err := http.Get("http://127.0.0.1:8001/api/balance?addrs="+ testaddress)
			if err != nil {log.Fatalln(err)}
			defer resp1.Body.Close()
			decoder := json.NewDecoder(resp1.Body)
			err = decoder.Decode(&q)
			if err != nil {log.Fatalln(err)}
			fmt.Printf("HTTP Response Status:\n%d\n%s\n", resp1.StatusCode, http.StatusText(resp1.StatusCode))
			fmt.Printf("Address\n")
			fmt.Println(string(testaddress))
			fmt.Printf("Current Coins:\n")
			fmt.Println(q.Confirmed.Coins)
			if q.Confirmed.Coins == 0 {
				fmt.Printf("Address is empty, Using:\n")
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
var CashCheckOutUrl string = "https://pay.magnetosphere.net/paywithcash"	// payment modal

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
