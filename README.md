lookupinvoice
===========

A simple function capable of checking the status of an invoice in multiple Lightning backends.

Currently supports Sparko, LND REST and LNbits.

## Usage

```go
package main

import "github.com/bumi/lookupinvoice"

func main () {
	bolt11, err := lookupinvoice.LookupInvoice(lookupinvoice.Params{
		paymentHash: "invoice payment hash,
		Backend: LNDParams{
			Host: "https://my.lnd.com:1234",
			Macaroon: "0201036c6e640258030a10e82b814c2a3871f9753984e0f5e01ffb1201301a160a0761646472657373120472656164120577726974651a170a08696e766f69636573120472656164120577726974651a0f0a076f6e636861696e1204726561640000062087d4b068ad6b4d912680b3e0d912ca02936733a3377f246aa32bf354aa74ab2d",
		}
	})
}
```
