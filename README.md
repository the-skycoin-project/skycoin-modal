# skycoin-modal

WIP skycoin payment modal web application for integration with snipcart.com as a custom payment gateway


Tested on [Archlinux](https://endeavouros.com/)

## Prerequisite

'make dependencies'[(*?)](https://wiki.archlinux.org/index.php/PKGBUILD#makedepends):
```
yay -S go hugo
```

golang 'make dependencies':
* live reload (for development)
```
go get github.com/pilu/fresh
sudo ln -s ~/go/bin/fresh /usr/bin/fresh
```
* creating new 'statik' gui sources
```
go get github.com/rakyll/statik
sudo ln -s ~/go/bin/statik /usr/bin/statik
```
(Alternatively, you can add GOBIN to your PATH)

'runtime dependencies'[(*?)](https://wiki.archlinux.org/index.php/PKGBUILD#depends):
* skycoin
```
yay -S skycoin-explorer skycoin-bin
```
* bitcoin / btcpayserver:
```
yay -S bitcoind nbxplorer btcpayserver
```
* privateness privateness-explorer
```
yay -S privateness
```

* Note: refer to [this pull request](https://github.com/skycoin/skycoin-explorer/pull/351) to build the skycoin explorer from source
* Note: nbxplorer and btcpayserver fail to build currently
* Note: a full bitcoin node may take up to 2 months to sync initially.
* Note: see release section for privateness explorer

## Sync Go Dependencies

Sync the needed golang dependencies
```
go mod init
go mod vendor -v
```

## Build or update the frontend with Hugo

Hugo is used to generate the html templates and page resources

**The escaped functions (which need to appear in the final template files generated by hugo) are defined in [config.toml](/config.toml)**

Build the front end
```
hugo
```

Live-editing the hugo templates is also possible; this is done independently of the web application.
```
hugo server -D
```

## Build or update the statik/statik.go file

generate the statik/statik.go file from the public dir which was generated by hugo above
```
statik -f -src=./public
```

updates the dependencies according to the above generated file
```
go generate
```

the contents of the `public` folder which was created by hugo in the previous step can now be compiled into the binary.


## Run the application
Note: to fully utilize this application you must run a [skycoin](https://github.com/skycoin/skycoin) node and an instance of the [skycoin-explorer](https://github.com/skycoin/skycoin-explorer) and complete some additional configuration. See below.
```
make fresh
```

starts on :
[http://127.0.0.1:8041](http://127.0.0.1:8041)

Non-breaking changes to the source code in main.go will be refreshed automatically.

## Building the binary

Note the contents of the Makefile and the envs required to run this. The configuration in this regard will be improved in the future. The instance used for development has some values hard-coded, these must be changed to ENVs or a configuration file scheme must be devised or a mechanism for prompting for user input to create such a configuration.

A simple `go build .` should suffice if you desire to compile a binary, assuming that statik/statik.go is present

## Production deployment

In the author's test environment, `caddy` server is used to reverse proxy the app port (:8041) to a subdomain of the main website.

example Caddyfile:
```
#store / main site
example.net {
reverse_proxy 127.0.0.1:8040
}
#skycoin-modal
pay.example.net {
reverse_proxy 127.0.0.1:8041
}
#btcpayserver
btc.example.net {
reverse_proxy 127.0.0.1:23000
}
#skycoin-explorer
skycoin.example.net {
reverse_proxy 127.0.0.1:8001
}
#ness-explorer
ness.example.net {
reverse_proxy 127.0.0.1:8002
}
```

Note: it is not required to have the privateness or skycoin explorers on their own subdomain, only running on the same machine.

## Snipcart Integration

In the payment methods request URL field of the [snipcart dashboard](https://app.snipcart.com/dashboard/account/gateway/customgateway) the following endpoint is specified:
```
https://pay.example.com/paywithskycoin
```

When placing an order; after the customer enters their shipping information and selects a shipping option, snipcart makes a POST request to the endpoint above, specified in the merchant dashboard. After verifying the request, a response is sent which is an array of payment options.

The array of payment option is then displayed for the customer, the previously configured ones in the merchant dashboard, as well as any which are specified in main.go

The customer selects a payment option provided by this custom payment gateway and lands on the payment modal (or a link to the btcpayserver payment modal)

The session is verified, the modal is generated with the next available address, the current rate of the cryptocurrency is used to calculate the payment request amount from the invoice amount in USD, and when payment has been completed, a POST request is sent to snipcart. In reply is the URL to redirect the customer to, and the customer is redirected to view their invoice.

## Generate Addresses

To display the correct addresses for your webstore, these addresses must be generated and defined in addresses.txt in the current working directory.

**NOTE: Do not have the wallet with the coins in the same environment or on the same machine as this for obvious security reasons**

Create the wallet addresses in a secure environment (using the wallet gui is most functional), create 100 addresses and export them to a file:
```
skycoin-cli listWallets
skycoin-cli listAddresses 2021_04_20_7ba7.wlt > sky-addresses.txt
```

NOTE FOR PRIVATENESS: the privateness-cli is glitchy at the moment, so save your wallet in your skycoin wallet dir and use skycoin-cli after opening the wallet in the GUI. (The addresses will be the same) save the json-formatted list of addresses output by skycoin-cli to `ness-addresses.txt`

Save these addresses somewhere in case you need to manually recover them.

Copy them to this repository in your test environment.

## Run a skycoin node

A gui instance of the skycoin wallet will suffice, but it **MUST NOT CONTAIN ANY COINS**

this is merely a runtimedependency of the skycoin explorer

You may use a hardware wallet or any single address quotated in place of the `nextAddress()` function.

I am unaware of how to create addresses with the hardware wallet. It may be possible with cli but it is not possible with the gui.

If using a single address you do not require to run a skycoin node or the skycoin explorer.

## Run the skycoin explorer

An archive of a working copy of the skycoin explorer for linux is provided.

Extract it somewhere, and from in that directory you can run the skycoin explorer with:

```
bin/skycoin-explorer
```

make sure your skycoin node is running on the default port :6420


## Run a Privateness Node

if using the AUR package
```
ness-wallet
```

the above section pertaining to skycoin still applies

## Run the Privateness Explorer

the easiest way for this example, download a copy of the explorer that is compiled to work with the Privateness wallet [127.0.0.1:6460](http://127.0.0.1:6460) and which runs on an adjacent port to the skycoin explorer [127.0.0.1:8002](http://127.0.0.1:8002)

## TO DO

Revise GUI

Autodetect payment / remove txid entry

Improve code formatting / reduce redundancy
