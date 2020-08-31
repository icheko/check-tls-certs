// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/certifi/gocertifi"
	"github.com/keighl/mandrill"
)

const currentVersion string = "1.1"

const defaultConcurrency = 8

//worker sleep duration (hours)
const SLEEP_DURATION = 24

type emailDetails struct {
	subject   string
	mail_text string
	mail_html string
}

type envVariables struct {
	api_key         string
	email_src_addr  string
	email_src_name  string
	email_dest_addr []string
}

const (
	errExpiringShortly      = "%s: ** '%s' (S/N %X) expires in %d hours! **"
	errExpiringSoon         = "%s: '%s' (S/N %X) expires in roughly %d days."
	errSunsetAlg            = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
	fmtCertInfo             = "%s: (S/N %X) expires in roughly %d days."
	fmtCertInfoNoExpiration = "%s: (S/N %X)"
	resultsCertInfo         = "CERT-INFO: %s (%s) found cert %s\n"
	resultsCertError        = "CERT-ERROR: %s\n"
	resultsError            = "ERROR: %s '%s'\n"
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

var (
	help         = flag.Bool("help", false, "Show help screen.")
	hostsFile    = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	warnYears    = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths   = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays     = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg  = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
	concurrency  = flag.Int("concurrency", defaultConcurrency, "Maximum number of hosts to check at once.")
	useIPV6      = flag.Bool("ipv6", false, "Use IPV6 to establish connections.")
	daemon       = flag.Bool("d", false, "Start in daemon mode.")
	info         = flag.Bool("info", false, "Print certificate info.")
	noTimeStamps = flag.Bool("nots", false, "Don't print timestamps in info/error messages.")
	compare      = flag.Bool("compare", false, "Easily compare results by exclusing timestamps and certificate expiration (implies -info, -nots).")
	sendEmail    = flag.Bool("sendemail", false, "Send email if certificate errors are found.")
	stdIn        = flag.Bool("stdin", false, "Read hosts from stdin.")
	timeout      = flag.Int("timeout", 15, "Connection timeout.")
	version      = flag.Bool("version", false, "Display version info.")
)

var hostsParameter string

type certErrors struct {
	commonName string
	errs       []error
}

type certInfo struct {
	commonName string
	info       string
}

type hostResult struct {
	host     string
	ip       string
	err      error
	certs    []certErrors
	certInfo certInfo
}

func main() {
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	if *version {
		fmt.Println("check-tls-certs version " + currentVersion)
		return
	}

	// checks
	if len(*hostsFile) == 0 && len(flag.Args()) == 0 && *stdIn == false {
		fmt.Print("Invalid Command: Missing -hosts flag or host parameter\n\n")
		printUsage()
		return
	}
	if len(*hostsFile) >= 1 && len(flag.Args()) >= 1 && *stdIn == false {
		fmt.Print("Invalid Command: Use either -hosts flag or host parameter\n\n")
		printUsage()
		return
	}
	if len(*hostsFile) == 0 && len(flag.Args()) >= 1 && *stdIn == false {
		hostsParameter = flag.Arg(0)
	}

	// defaults
	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	if *concurrency < 0 {
		*concurrency = defaultConcurrency
	}
	if *compare {
		*info = true
		*noTimeStamps = true
	}

	if *daemon {
		for {
			startUp()
			log.Println("done. going away for", SLEEP_DURATION, "hours")
			time.Sleep(SLEEP_DURATION * time.Hour)
		}
	} else {
		startUp()
	}
}

func startUp() {
	log.Println("checking ssl certs ...")
	if *useIPV6 {
		log.Println("Using IPV6")
	}
	processHosts()
}

func printUsage() {
	fmt.Print("check-tls-certs [-flag value] [host]\n\n")
	flag.Usage()
	fmt.Println()
}

func buildErrorMessage(host, error string) string {
	if *noTimeStamps {
		return fmt.Sprintf(resultsError, host, error)
	}

	return fmt.Sprintf("%s "+resultsError, getCurrentTime(), host, error)
}

func buildCertErrorMessage(error string) string {
	if *noTimeStamps {
		return fmt.Sprintf(resultsCertError, error)
	}

	return fmt.Sprintf("%s "+resultsCertError, getCurrentTime(), error)
}

func buildCertInfoMessage(host, ip, info string) string {
	if *noTimeStamps {
		return fmt.Sprintf(resultsCertInfo, host, ip, info)
	}

	return fmt.Sprintf("%s "+resultsCertInfo, getCurrentTime(), host, ip, info)
}

func processHosts() {
	done := make(chan struct{})
	defer close(done)

	hosts := queueHosts(done)
	results := make(chan hostResult)

	var wg sync.WaitGroup
	wg.Add(*concurrency)
	for i := 0; i < *concurrency; i++ {
		go func() {
			processQueue(done, hosts, results)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var certMessages, certInfoMessages string
	var resultsSorted []hostResult

	for r := range results {
		resultsSorted = append(resultsSorted, r)
	}

	sort.SliceStable(resultsSorted, func(i, j int) bool {
		var hostiLower = strings.ToLower(resultsSorted[i].host)
		var hostjLower = strings.ToLower(resultsSorted[j].host)
		var hostiIP = net.ParseIP(getHost(resultsSorted[i].ip))
		var hostjIP = net.ParseIP(getHost(resultsSorted[j].ip))

		if hostiLower == hostjLower {
			return bytes.Compare(hostiIP, hostjIP) < 0
		}
		return hostiLower < hostjLower
	})

	for _, r := range resultsSorted {
		// connection errors, etc
		if r.err != nil {
			certMessages += buildErrorMessage(r.host, r.err.Error())
			continue
		}
		// cert errors
		for _, cert := range r.certs {
			for _, err := range cert.errs {
				certMessages += buildCertErrorMessage(err.Error())
			}
		}
		// cert info
		if r.certInfo != (certInfo{}) {
			certInfoMessages += buildCertInfoMessage(r.host, r.ip, r.certInfo.info)
		}
	}

	if certInfoMessages != "" && *info {
		fmt.Println(certInfoMessages)
	}

	if *compare {
		return
	}

	if certMessages == "" {
		log.Printf("No certificate is expiring in %d years, %d months, %d days", *warnYears, *warnMonths, *warnDays)
		return
	}

	fmt.Println(certMessages)

	if *sendEmail {
		emailDetails := &emailDetails{}
		emailDetails.subject = "Heroku app - check certificate details"
		emailDetails.mail_text = certMessages
		sendMail(emailDetails)
	}

	os.Exit(1)
}

// return current time in YYYY-MM-dd HH:mm:ss
func getCurrentTime() string {
	t := time.Now()
	currentTime := fmt.Sprintf("%d/%02d/%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return currentTime
}

func removeNewLineChar(str string) string {
	if strings.Contains(str, "\n") {
		return strings.Replace(str, "\n", "", 1)
	}

	return str
}

func queueHosts(done <-chan struct{}) <-chan string {
	hosts := make(chan string)
	go func() {
		defer close(hosts)

		var lines []string

		if *hostsFile != "" {
			fileContents, err := ioutil.ReadFile(*hostsFile)
			if err != nil {
				return
			}
			lines = strings.Split(string(fileContents), "\n")
		} else if hostsParameter != "" {
			lines = strings.Split(hostsParameter, ",")
		} else {
			reader := bufio.NewReader(os.Stdin)

			for {
				input, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				input = removeNewLineChar(input)
				lines = append(lines, input)
			}
		}

		for _, line := range lines {
			host := strings.TrimSpace(line)
			if len(host) == 0 || host[0] == '#' {
				continue
			}
			host = addDefaultSSLPort(host)
			select {
			case hosts <- host:
			case <-done:
				return
			}
		}
	}()
	return hosts
}

func processQueue(done <-chan struct{}, hosts <-chan string, results chan<- hostResult) {
	for host := range hosts {
		ips, err := getIPsWithPort(host)
		if err != nil {
			results <- hostResult{
				host: host,
				err:  err,
			}
		}
		for _, ip := range ips {
			select {
			case results <- checkHost(ip, host):
			case <-done:
				return
			}
		}
	}
}

func addDefaultSSLPort(host string) string {
	if !strings.Contains(host, ":") {
		return host + ":443"
	}

	return host
}

func getIPsWithPort(host string) ([]string, error) {
	filteredIps := []string{}
	ips, err := getIPs(getHost(host))
	for _, ip := range ips {
		if *useIPV6 == false && isIPv4(ip) {
			filteredIps = append(filteredIps, ip+":"+getPort(host))
		} else if *useIPV6 == true && isIPv6(ip) {
			filteredIps = append(filteredIps, "["+ip+"]:"+getPort(host))
		}
	}

	return filteredIps, err
}

func isIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func getIPs(host string) ([]string, error) {
	ips, err := net.LookupHost(host)
	return ips, err
}

func getHost(host string) string {
	result := strings.Split(host, ":")
	return result[0]
}

func getPort(host string) string {
	result := strings.Split(host, ":")
	return result[1]
}

func checkHost(ip string, host string) (result hostResult) {
	result = hostResult{
		host:  host,
		ip:    ip,
		certs: []certErrors{},
	}

	//load ca certs. bundle
	certPool, err := gocertifi.CACerts()
	config := tls.Config{
		RootCAs:    certPool,
		ServerName: getHost(host),
	}

	ipConn, err := net.DialTimeout("tcp", ip, time.Duration(*timeout)*time.Second)

	if err != nil {
		result.err = err
		return
	}
	defer ipConn.Close()

	// fmt.Printf("%s DEBUG: Client connected to %s\n", getCurrentTime(), ipConn.RemoteAddr())

	conn := tls.Client(ipConn, &config)
	defer conn.Close()

	// Handshake with TLS to get cert
	hsErr := conn.Handshake()
	if hsErr != nil {
		result.certs = append(result.certs, certErrors{
			errs: append([]error{}, fmt.Errorf("%v (%v) %s", config.ServerName, ip, hsErr.Error())),
		})
		return
	}
	// fmt.Printf("%s DEBUG: TLS Handshake succeeded for %s\n", getCurrentTime(), conn.RemoteAddr())

	timeNow := time.Now()
	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}
			cErrs := []error{}
			expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())

			// Check the expiration.
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				if expiresIn <= 48 {
					cErrs = append(cErrs, fmt.Errorf(errExpiringShortly, cert.Subject.CommonName, ip, cert.SerialNumber, expiresIn))
				} else {
					cErrs = append(cErrs, fmt.Errorf(errExpiringSoon, cert.Subject.CommonName, ip, cert.SerialNumber, expiresIn/24))
				}
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					cErrs = append(cErrs, fmt.Errorf(errSunsetAlg, cert.Subject.CommonName, ip, cert.SerialNumber, alg.name))
				}
			}

			if *info && certNum == 0 {
				var info string
				if *compare {
					info = fmt.Sprintf(fmtCertInfoNoExpiration, cert.Subject.CommonName, cert.SerialNumber)
				} else {
					info = fmt.Sprintf(fmtCertInfo, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24)
				}
				result.certInfo = certInfo{
					commonName: cert.Subject.CommonName,
					info:       info,
				}
			}

			result.certs = append(result.certs, certErrors{
				commonName: cert.Subject.CommonName,
				errs:       cErrs,
			})
		}
	}

	return
}

//get mandrill api key & mail parameters from shell env.
func getOSEnv() envVariables {
	os_env_vars := &envVariables{}
	os_env_vars.api_key = os.Getenv("MANDRILL_KEY")
	os_env_vars.email_src_addr = os.Getenv("EMAIL_SRC_ADDR")
	os_env_vars.email_src_name = os.Getenv("EMAIL_SRC_NAME")
	os_env_vars.email_dest_addr = strings.Split(os.Getenv("EMAIL_DEST_ADDR"), " ")

	return *os_env_vars
}

// send mail notification to admin(s)
func sendMail(mail_details *emailDetails) {
	os_env_vars := getOSEnv()

	//validate os env vars. fail otherwise!
	if os_env_vars.api_key == "" {
		log.Println("OS env variable 'MANDRILL_KEY' is not defined!")
		os.Exit(2)
	} else if len(os_env_vars.email_dest_addr) <= 0 {
		log.Println("OS env variable 'EMAIL_DEST_ADDR' is not defined!")
		os.Exit(2)
	} else if os_env_vars.email_src_addr == "" {
		log.Println("OS env variable 'EMAIL_SRC_ADDR' is not defined!")
		os.Exit(2)
	}

	client := mandrill.ClientWithKey(os_env_vars.api_key)

	message := &mandrill.Message{}
	message.FromEmail = os_env_vars.email_src_addr
	message.FromName = os_env_vars.email_src_name
	for _, recipient := range os_env_vars.email_dest_addr {
		message.AddRecipient(recipient, "", "to")
	}
	message.Subject = mail_details.subject
	message.Text = mail_details.mail_text
	if mail_details.mail_html != "" {
		message.HTML = mail_details.mail_html
	}

	//send the mail(s)
	responses, err := client.MessagesSend(message)

	//show error details if mail(s) not sent
	if err != nil {
		fmt.Println("Unable to send mail(s)" + err.Error())
		for _, response := range responses {
			log.Printf("Unable to send mail to %s. Reason: %s", response.Email, response.RejectionReason)
		}
	} else {
		log.Println("Mail(s) sent!")
	}
}
