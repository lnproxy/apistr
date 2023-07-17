package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/lnproxy/apistr"
	"github.com/lnproxy/lnc"
	"github.com/lnproxy/lnproxy-relay"
)

type URLs []url.URL

func (us *URLs) String() string {
	var sb strings.Builder
	for _, u := range *us {
		sb.WriteString(u.String())
		sb.WriteString("\n")
	}
	return sb.String()
}

func (us *URLs) Set(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}
	*us = append(*us, *u)
	return nil
}

var (
	lnproxy_relay *relay.Relay

	isInvoice = regexp.MustCompile("^[[:space:]]*lnbc(?:[0-9]+[pnum])?1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+[[:space:]]*$")
)

func apiHandler(ctx context.Context, conversation chan string) {
	defer close(conversation)
	x := relay.ProxyParameters{}
	var simple bool

	request_string := <-conversation
	request := []byte(request_string)

	if isInvoice.Match(request) {
		simple = true
		x.Invoice = strings.TrimSpace(request_string)
	} else {
		err := json.Unmarshal(request, &x)
		if err != nil {
			log.Println("error decoding content:", request_string)
			conversation <- jsonError("bad request")
			return
		}
	}

	proxy_invoice, err := lnproxy_relay.OpenCircuit(x)
	if errors.Is(err, relay.ClientFacing) {
		log.Println(x, "client facing error", err)
		conversation <- jsonError(strings.TrimSpace(err.Error()))
		return
	} else if err != nil {
		log.Println(x, "internal error", err)
		conversation <- jsonError("internal error")
		return
	}

	if simple {
		conversation <- proxy_invoice
	} else {
		conversation <- fmt.Sprintf(`{"proxy_invoice": "%s"}`, proxy_invoice)
	}
}

func jsonError(reason string) string {
	return fmt.Sprintf(`{"status":"ERROR","reason":"%s"}`, reason)
}

func main() {
	nostrRelays := make(URLs, 0, 2)
	flag.Var(&nostrRelays, "relay", "relay url to read from, can be set multiple times")
	lndHostString := flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndCertPath := flag.String(
		"lnd-cert",
		".lnd/tls.cert",
		"lnd's self-signed cert (set to empty string for no-rest-tls=true)",
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `usage: %s [flags] lnproxy.macaroon private.key
  lnproxy.macaroon
	Path to lnproxy macaroon. Generate it with:
		lncli bakemacaroon --save_to lnproxy.macaroon \
			uri:/lnrpc.Lightning/DecodePayReq \
			uri:/lnrpc.Lightning/LookupInvoice \
			uri:/invoicesrpc.Invoices/AddHoldInvoice \
			uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
			uri:/invoicesrpc.Invoices/CancelInvoice \
			uri:/invoicesrpc.Invoices/SettleInvoice \
			uri:/routerrpc.Router/SendPaymentV2 \
			uri:/routerrpc.Router/EstimateRouteFee \
			uri:/chainrpc.ChainKit/GetBestBlock
  private.key
	Path to nostr private key in hex. Generate it with your favorite nostr client.
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.Parse()
	if len(flag.Args()) != 2 {
		flag.Usage()
		os.Exit(2)
	}

	macaroonBytes, err := os.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatalln("unable to read lnproxy macaroon file:", err)
	}
	macaroon := hex.EncodeToString(macaroonBytes)

	lndHost, err := url.Parse(*lndHostString)
	if err != nil {
		log.Fatalln("unable to parse lnd host url:", err)
	}
	// If this is not set then websocket errors:
	lndHost.Path = "/"

	var lndTlsConfig *tls.Config
	if *lndCertPath == "" {
		lndTlsConfig = &tls.Config{}
	} else {
		lndCert, err := os.ReadFile(*lndCertPath)
		if err != nil {
			log.Fatalln("unable to read lnd tls certificate file:", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(lndCert)
		lndTlsConfig = &tls.Config{RootCAs: caCertPool}
	}

	lndClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: lndTlsConfig,
		},
	}

	lnd := &lnc.Lnd{
		Host:      lndHost,
		Client:    lndClient,
		TlsConfig: lndTlsConfig,
		Macaroon:  macaroon,
	}

	lnproxy_relay = relay.NewRelay(lnd)

	privateKeyBytes, err := os.ReadFile(flag.Args()[1])
	if err != nil {
		log.Fatalln("unable to read nostr private key:", err)
	}

	server := apistr.Server{
		RelayURLs:  nostrRelays,
		PrivateKey: strings.TrimSpace(string(privateKeyBytes)),
		Handler:    apiHandler,
	}

	log.Println("relaying as:", server.PublicKey())

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		server.Shutdown()
		close(idleConnsClosed)
		log.Println("stopped reading from relays")
	}()
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Println("nostr relay server error:", err)
		}
	}()
	<-idleConnsClosed

	signal.Reset(os.Interrupt)
	log.Println("waiting for open circuits...")
	lnproxy_relay.WaitGroup.Wait()
}
