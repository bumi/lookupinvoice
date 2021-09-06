package lookupinvoice

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	lightning "github.com/fiatjaf/lightningd-gjson-rpc"
	"github.com/tidwall/gjson"
)

var TorProxyURL = "socks5://127.0.0.1:9050"

type Params struct {
	Backend     BackendParams
	paymentHash string
}

type SparkoParams struct {
	Cert string
	Host string
	Key  string
}

func (l SparkoParams) getCert() string { return l.Cert }
func (l SparkoParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNDParams struct {
	Cert     string
	Host     string
	Macaroon string
}

func (l LNDParams) getCert() string { return l.Cert }
func (l LNDParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNBitsParams struct {
	Cert string
	Host string
	Key  string
}

func (l LNBitsParams) getCert() string { return l.Cert }
func (l LNBitsParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNPayParams struct {
	PublicAccessKey  string
	WalletInvoiceKey string
}

func (l LNPayParams) getCert() string { return "" }
func (l LNPayParams) isTor() bool     { return false }

type BackendParams interface {
	getCert() string
	isTor() bool
}

type Invoice struct {
	Settled bool
	Status  string
}

func LookupInvoice(params Params) (invoice Invoice, err error) {
	defer func(prevTransport http.RoundTripper) {
		http.DefaultClient.Transport = prevTransport
	}(http.DefaultClient.Transport)

	specialTransport := &http.Transport{}

	// use a cert or skip TLS verification?
	if params.Backend.getCert() != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(params.Backend.getCert()))
		specialTransport.TLSClientConfig = &tls.Config{RootCAs: caCertPool}
	} else {
		specialTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// use a tor proxy?
	if params.Backend.isTor() {
		torURL, _ := url.Parse(TorProxyURL)
		specialTransport.Proxy = http.ProxyURL(torURL)
	}

	http.DefaultClient.Transport = specialTransport

	// set a timeout
	http.DefaultClient.Timeout = 15 * time.Second

	switch backend := params.Backend.(type) {
	case SparkoParams:
		spark := &lightning.Client{
			SparkURL:    backend.Host,
			SparkToken:  backend.Key,
			CallTimeout: time.Second * 3,
		}

		inv, err := spark.Call("listinvoices", nil, nil, params.paymentHash, nil)
		if err != nil {
			return Invoice{}, fmt.Errorf("listinvoices call failed: %w", err)
		}
		return Invoice{
			Settled: inv.Get("status").String() == "paid",
		}, nil

	case LNDParams:
		req, err := http.NewRequest("GET",
			backend.Host+"/v1/invoice/"+params.paymentHash,
			nil,
		)
		if err != nil {
			return Invoice{}, err
		}

		// macaroon must be hex, so if it is on base64 we adjust that
		if b, err := base64.StdEncoding.DecodeString(backend.Macaroon); err == nil {
			backend.Macaroon = hex.EncodeToString(b)
		}

		req.Header.Set("Grpc-Metadata-macaroon", backend.Macaroon)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return Invoice{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(resp.Body)
			text := string(body)
			if len(text) > 300 {
				text = text[:300]
			}
			return Invoice{}, fmt.Errorf("call to lnd failed (%d): %s", resp.StatusCode, text)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return Invoice{}, err
		}

		parsedBody := gjson.ParseBytes(b)
		return Invoice{
			Settled: parsedBody.Get("settled").Bool(),
		}, nil

	case LNBitsParams:
		req, err := http.NewRequest("GET",
			backend.Host+"/api/v1/payments"+params.paymentHash,
			nil,
		)
		if err != nil {
			return Invoice{}, err
		}

		req.Header.Set("X-Api-Key", backend.Key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return Invoice{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(resp.Body)
			text := string(body)
			if len(text) > 300 {
				text = text[:300]
			}
			return Invoice{}, fmt.Errorf("call to lnbits failed (%d): %s", resp.StatusCode, text)
		}

		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return Invoice{}, err
		}

		return Invoice{
			Settled: gjson.ParseBytes(b).Get("paid").Bool(),
		}, nil
	}
	return Invoice{}, errors.New("missing backend params")
}
