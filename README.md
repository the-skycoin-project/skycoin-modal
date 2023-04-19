# skycoin-modal

snipcart.com as a custom payment gateway for skycoin and bitcoin checkout

## Prerequisite

'runtime dependencies'[(*?)](https://wiki.archlinux.org/index.php/PKGBUILD#depends):
* skycoin-explorer & skycoin wallet
```
yay -S skycoin-explorer skycoin-bin
```
* electrum wallet
```
yay -S electrum
```

## Sync Go Dependencies

Sync the needed golang dependencies
```
go mod init ; go mod tidy ; go mod vendor
```


## Run the application
Note: to fully utilize this application you must run a [skycoin](https://github.com/skycoin/skycoin) node and an instance of the [skycoin-explorer](https://github.com/skycoin/skycoin-explorer) and complete some additional configuration. See below.
```
export APIKEY=your_private_snipcart_api_key
export WALLETPATH=/path/to/electrum/wallet
go run g8.go
```


## Snipcart Integration

In the payment methods request URL field of the [snipcart dashboard](https://app.snipcart.com/dashboard/account/gateway/customgateway) the following endpoint is specified:
```
https://pay.example.com/paywithskycoin
```

When placing an order; after the customer enters their shipping information and selects a shipping option, snipcart makes a POST request to the endpoint above, specified in the merchant dashboard. After verifying the request, a response is sent which is an array of payment options.

The array of payment option is then displayed for the customer, the previously configured ones in the merchant dashboard, as well as any which are specified in main.go

The customer selects a payment option provided by this custom payment gateway and lands on the payment modal (or a link to the btcpayserver payment modal)

## Generate Addresses

To display the correct addresses for your webstore, these addresses must be generated and defined in addresses.txt in the current working directory.

**NOTE: Do not have the wallet with the coins in the same environment or on the same machine as this for obvious security reasons**

Create the wallet addresses in a secure environment (using the wallet gui is most functional), create 100 addresses and export them to a file:
```
skycoin-cli listWallets
skycoin-cli listAddresses 2021_04_20_7ba7.wlt > sky-addresses.txt
```

Save these addresses somewhere in case you need to manually recover them.

Copy them to this repository in your test environment.
