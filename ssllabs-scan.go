// +build go1.3

/*
 * Licensed to Qualys, Inc. (QUALYS) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * QUALYS licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	LogNone     = -1
	LogEmerg    = 0
	LogAlert    = 1
	LogCritical = 2
	LogError    = 3
	LogWarning  = 4
	LogNotice   = 5
	LogInfo     = 6
	LogDebug    = 7
	LogTrace    = 8
)

const UserAgent = "ssllabs-scan v1.1.0 ($Id$)"

var (
	logLevel             = LogNotice
	activeAssessments    = 0
	maxAssessments       = -1
	apiLocation          = "https://api.ssllabs.com/api/v2"
	globalIgnoreMismatch = false
	globalStartNew       = true
	globalFromCache      = false
	globalMaxAge         = 0
	globalInsecure       = false
)

var (
	requestCounter uint64
	httpClient     *http.Client
)

type LabsError struct {
	Field   string
	Message string
}

type LabsErrorResponse struct {
	ResponseErrors []LabsError `json:"errors"`
}

func (e LabsErrorResponse) Error() string {
	msg, err := json.Marshal(e)
	if err != nil {
		return err.Error()
	}
	return string(msg)
}

type LabsKey struct {
	Size       int
	Strength   int
	Alg        string
	DebianFlaw bool
	Q          int
}

type LabsCert struct {
	Subject              string
	CommonNames          []string
	AltNames             []string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	SigAlg               string
	IssuerLabel          string
	RevocationInfo       int
	CrlURIs              []string
	OcspURIs             []string
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Sgc                  int
	ValidationType       string
	Issues               int
	Sct                  bool
}

type LabsChainCert struct {
	Subject              string
	Label                string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	IssuerLabel          string
	SigAlg               string
	Issues               int
	KeyAlg               string
	KeySize              int
	KeyStrength          int
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Raw                  string
}

type LabsChain struct {
	Certs  []LabsChainCert
	Issues int
}

type LabsProtocol struct {
	ID               int
	Name             string
	Version          string
	V2SuitesDisabled bool
	ErrorMessage     bool
	Q                int
}

type LabsSimClient struct {
	ID          int
	Name        string
	Platform    string
	Version     string
	IsReference bool
}

type LabsSimulation struct {
	Client     LabsSimClient
	ErrorCode  int
	Attempts   int
	ProtocolID int
	SuiteID    int
}

type LabsSimDetails struct {
	Results []LabsSimulation
}

type LabsSuite struct {
	ID             int
	Name           string
	CipherStrength int
	DhStrength     int
	DhP            int
	DhG            int
	DhYs           int
	EcdhBits       int
	EcdhStrength   int
	Q              int
}

type LabsSuites struct {
	List       []LabsSuite
	Preference bool
}

type LabsEndpointDetails struct {
	HostStartTime                  int64
	Key                            LabsKey
	Cert                           LabsCert
	Chain                          LabsChain
	Protocols                      []LabsProtocol
	Suites                         LabsSuites
	ServerSignature                string
	PrefixDelegation               bool
	NonPrefixDelegation            bool
	VulnBeast                      bool
	RenegSupport                   int
	StsResponseHeader              string
	StsMaxAge                      int64
	StsSubdomains                  bool
	PkpResponseHeader              string
	SessionResumption              int
	CompressionMethods             int
	SupportsNpn                    bool
	NpnProtocols                   string
	SessionTickets                 int
	OcspStapling                   bool
	StaplingRevocationStatus       int
	StaplingRevocationErrorMessage string
	SniRequired                    bool
	HTTPStatusCode                 int
	HTTPForwarding                 string
	SupportsRc4                    bool
	ForwardSecrecy                 int
	Rc4WithModern                  bool
	Sims                           LabsSimDetails
	Heartbleed                     bool
	Heartbeat                      bool
	OpenSslCcs                     int
	Poodle                         bool
	PoodleTLS                      int
	FallbackScsv                   bool
	Freak                          bool
	HasSct                         int
}

type LabsEndpoint struct {
	IPAddress            string
	ServerName           string
	StatusMessage        string
	StatusDetailsMessage string
	Grade                string
	GradeTrustIgnored    string
	HasWarnings          bool
	IsExceptional        bool
	Progress             int
	Duration             int
	Eta                  int
	Delegation           int
	Details              LabsEndpointDetails
}

type LabsReport struct {
	Host            string
	Port            int
	Protocol        string
	IsPublic        bool
	Status          string
	StatusMessage   string
	StartTime       int64
	TestTime        int64
	EngineVersion   string
	CriteriaVersion string
	CacheExpiryTime int64
	Endpoints       []LabsEndpoint
	CertHostnames   []string
	rawJSON         string
}

type LabsResults struct {
	reports   []LabsReport
	responses []string
}

type LabsInfo struct {
	EngineVersion      string
	CriteriaVersion    string
	MaxAssessments     int
	CurrentAssessments int
	Messages           []string
}

func invokeGetRepeatedly(url string) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqID = atomic.AddUint64(&requestCounter, 1)

		if logLevel >= LogDebug {
			log.Printf("[DEBUG] Request #%v: %v", reqID, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", UserAgent)

		resp, err := httpClient.Do(req)
		if err == nil {
			if logLevel >= LogDebug {
				log.Printf("[DEBUG] Response #%v status: %v %v", reqID, resp.Proto, resp.Status)
			}

			if logLevel >= LogTrace {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if logLevel >= LogNotice {
				for key, values := range resp.Header {
					if strings.ToLower(key) == "x-message" {
						for _, value := range values {
							log.Printf("[NOTICE] Server message: %v\n", value)
						}
					}
				}
			}

			// Adjust maximum concurrent requests.

			headerValue := resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if maxAssessments != i {
						maxAssessments = i

						if logLevel >= LogDebug {
							log.Printf("[DEBUG] Server set max concurrent assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LogWarning {
						log.Printf("[WARNING] Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Retrieve the response body.

			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, nil, err
			}

			if logLevel >= LogTrace {
				log.Printf("[TRACE] Response #%v body:\n%v", reqID, string(body))
			}

			return resp, body, nil
		}

		if err.Error() == "EOF" {
			// Server closed a persistent connection on us, which
			// Go doesn't seem to be handling well. So we'll try one
			// more time.
			if retryCount > 5 {
				log.Fatalf("[ERROR] Too many HTTP requests failed with EOF")
			}

			if logLevel >= LogDebug {
				log.Printf("[DEBUG] HTTP request failed with EOF")
			}
		} else {
			log.Fatalf("[ERROR] HTTP request failed: %v", err)
		}

		retryCount++
	}
}

func invokeAPI(command string) (*http.Response, []byte, error) {
	var url = apiLocation + "/" + command

	for {
		resp, body, err := invokeGetRepeatedly(url)
		if err != nil {
			return nil, nil, err
		}

		// Status codes 429, 503, and 529 essentially mean try later. Thus,
		// if we encounter them, we sleep for a while and try again.
		if resp.StatusCode == 429 {
			if logLevel >= LogNotice {
				log.Printf("[NOTICE] Sleeping for 30 seconds after a %v response", resp.StatusCode)
			}

			time.Sleep(30 * time.Second)
		} else if (resp.StatusCode == 503) || (resp.StatusCode == 529) {
			// In case of the overloaded server, randomize the sleep time so
			// that some clients reconnect earlier and some later.

			sleepTime := 15 + rand.Int31n(15)

			if logLevel >= LogNotice {
				log.Printf("[NOTICE] Sleeping for %v minutes after a %v response", sleepTime, resp.StatusCode)
			}

			time.Sleep(time.Duration(sleepTime) * time.Minute)
		} else if (resp.StatusCode != 200) && (resp.StatusCode != 400) {
			log.Fatalf("[ERROR] Unexpected response status code %v", resp.StatusCode)
		} else {
			return resp, body, nil
		}
	}
}

func invokeInfo() (*LabsInfo, error) {
	var command = "info"

	_, body, err := invokeAPI(command)
	if err != nil {
		return nil, err
	}

	var labsInfo LabsInfo
	err = json.Unmarshal(body, &labsInfo)
	if err != nil {
		return nil, err
	}

	return &labsInfo, nil
}

func invokeAnalyze(host string, startNew bool, fromCache bool) (*LabsReport, error) {
	var command = "analyze?host=" + host + "&all=done"

	if fromCache {
		command = command + "&fromCache=on"

		if globalMaxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(globalMaxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if globalIgnoreMismatch {
		command = command + "&ignoreMismatch=on"
	}

	resp, body, err := invokeAPI(command)
	if err != nil {
		return nil, err
	}

	// Use the status code to determine if the response is an error.
	if resp.StatusCode == 400 {
		// Parameter validation error.

		var apiError LabsErrorResponse
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			return nil, err
		}

		return nil, apiError
	}

	// We should have a proper response.
	var analyzeResponse LabsReport
	err = json.Unmarshal(body, &analyzeResponse)
	if err != nil {
		return nil, err
	}

	// Add the JSON body to the response
	analyzeResponse.rawJSON = string(body)

	return &analyzeResponse, nil
}

type Event struct {
	host      string
	eventType int
	report    *LabsReport
}

const (
	AssessmentStarting = 0
	AssessmentComplete = 1
)

func NewAssessment(host string, eventChannel chan Event) {
	eventChannel <- Event{host, AssessmentStarting, nil}

	var report *LabsReport
	var startTime int64 = -1
	var startNew = globalStartNew

	for {
		myResponse, err := invokeAnalyze(host, startNew, globalFromCache)
		if err != nil {
			log.Fatalf("[ERROR] API invocation failed: %v", err)
		}

		if startTime == -1 {
			startTime = myResponse.StartTime
			startNew = false
		} else {
			if myResponse.StartTime != startTime {
				log.Fatalf("[ERROR] Inconsistent startTime. Expected %v, got %v.", startTime, myResponse.StartTime)
			}
		}

		if (myResponse.Status == "READY") || (myResponse.Status == "ERROR") {
			report = myResponse
			break
		}

		time.Sleep(5 * time.Second)
	}

	eventChannel <- Event{host, AssessmentComplete, report}
}

type HostProvider struct {
	hostnames []string
	i         int
}

func NewHostProvider(hs []string) *HostProvider {
	hostProvider := HostProvider{hs, 0}
	return &hostProvider
}

func (hp *HostProvider) next() (string, bool) {
	if hp.i < len(hp.hostnames) {
		host := hp.hostnames[hp.i]
		hp.i = hp.i + 1
		return host, true
	}
	return "", false
}

type Manager struct {
	hostProvider         *HostProvider
	FrontendEventChannel chan Event
	BackendEventChannel  chan Event
	results              *LabsResults
}

func NewManager(hostProvider *HostProvider) *Manager {
	manager := Manager{
		hostProvider:         hostProvider,
		FrontendEventChannel: make(chan Event),
		BackendEventChannel:  make(chan Event),
		results:              &LabsResults{reports: make([]LabsReport, 0)},
	}

	go manager.run()

	return &manager
}

func (manager *Manager) startAssessment(h string) {
	go NewAssessment(h, manager.BackendEventChannel)
	activeAssessments++
}

func (manager *Manager) run() {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: globalInsecure},
		DisableKeepAlives: true,
		Proxy:             http.ProxyFromEnvironment,
	}

	httpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo()
	if err != nil {
		// TODO Signal error so that we return the correct exit code
		close(manager.FrontendEventChannel)
	}

	if logLevel >= LogInfo {
		log.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if logLevel >= LogNotice {
		for _, message := range labsInfo.Messages {
			log.Printf("[NOTICE] Server message: %v", message)
		}
	}

	maxAssessments = labsInfo.MaxAssessments

	if maxAssessments <= 0 {
		if logLevel >= LogWarning {
			log.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	moreAssessments := true

	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.BackendEventChannel:
			if e.eventType == AssessmentStarting {
				if logLevel >= LogInfo {
					log.Printf("[INFO] Assessment starting: %v", e.host)
				}
			}

			if e.eventType == AssessmentComplete {
				if logLevel >= LogInfo {
					msg := ""

					// Missing C's ternary operator here.
					if len(e.report.Endpoints) == 0 {
						msg = fmt.Sprintf("[WARN] Assessment failed: %v (%v)", e.host, e.report.StatusMessage)
					} else if len(e.report.Endpoints) > 1 {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v hosts in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					} else {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v host in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					}

					for _, endpoint := range e.report.Endpoints {
						if endpoint.Grade != "" {
							msg = msg + "\n    " + endpoint.IPAddress + ": " + endpoint.Grade
						} else {
							msg = msg + "\n    " + endpoint.IPAddress + ": Err: " + endpoint.StatusMessage
						}
					}

					log.Println(msg)
				}

				activeAssessments--

				manager.results.reports = append(manager.results.reports, *e.report)
				manager.results.responses = append(manager.results.responses, e.report.rawJSON)

				if logLevel >= LogDebug {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeAssessments, moreAssessments)
				}

				// Are we done?
				if (activeAssessments == 0) && (moreAssessments == false) {
					close(manager.FrontendEventChannel)
					return
				}
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Second).C
			if moreAssessments {
				if activeAssessments < maxAssessments {
					host, hasNext := manager.hostProvider.next()
					if hasNext {
						manager.startAssessment(host)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreAssessments = false

						if activeAssessments == 0 {
							close(manager.FrontendEventChannel)
							return
						}
					}
				}
			}
			break
		}
	}
}

func parseLogLevel(level string) int {
	switch {
	case level == "error":
		return LogError
	case level == "notice":
		return LogNotice
	case level == "info":
		return LogInfo
	case level == "debug":
		return LogDebug
	case level == "trace":
		return LogTrace
	}

	log.Fatalf("[ERROR] Unrecognized log level: %v", level)
	return -1
}

func flattenJSON(inputJSON map[string]interface{}, rootKey string, flattened *map[string]interface{}) {
	var keysep = "." // Char to separate keys
	var Q = "\""     // Char to envelope strings

	for rkey, value := range inputJSON {
		key := rootKey + rkey
		if _, ok := value.(string); ok {
			(*flattened)[key] = Q + value.(string) + Q
		} else if _, ok := value.(float64); ok {
			(*flattened)[key] = fmt.Sprintf("%.f", value)
		} else if _, ok := value.(bool); ok {
			(*flattened)[key] = value.(bool)
		} else if _, ok := value.([]interface{}); ok {
			for i := 0; i < len(value.([]interface{})); i++ {
				aKey := key + keysep + strconv.Itoa(i)
				if _, ok := value.([]interface{})[i].(string); ok {
					(*flattened)[aKey] = Q + value.([]interface{})[i].(string) + Q
				} else if _, ok := value.([]interface{})[i].(float64); ok {
					(*flattened)[aKey] = value.([]interface{})[i].(float64)
				} else if _, ok := value.([]interface{})[i].(bool); ok {
					(*flattened)[aKey] = value.([]interface{})[i].(bool)
				} else {
					flattenJSON(value.([]interface{})[i].(map[string]interface{}), key+keysep+strconv.Itoa(i)+keysep, flattened)
				}
			}
		} else if value == nil {
			(*flattened)[key] = nil
		} else {
			flattenJSON(value.(map[string]interface{}), key+keysep, flattened)
		}
	}
}

func flattenAndFormatJSON(inputJSON []byte) *[]string {
	var flattened = make(map[string]interface{})

	mappedJSON := map[string]interface{}{}
	err := json.Unmarshal(inputJSON, &mappedJSON)
	if err != nil {
		log.Fatalf("[ERROR] Reconsitution of JSON failed: %v", err)
	}

	// Flatten the JSON structure, recursively
	flattenJSON(mappedJSON, "", &flattened)

	// Make a sorted index, so we can print keys in order
	index := make([]string, len(flattened))
	ki := 0
	for key := range flattened {
		index[ki] = key
		ki++
	}
	sort.Strings(index)

	// Ordered flattened data
	var flatStrings []string
	for _, value := range index {
		flatStrings = append(flatStrings, fmt.Sprintf("\"%v\": %v\n", value, flattened[value]))
	}
	return &flatStrings
}

func readLines(path *string) ([]string, error) {
	file, err := os.Open(*path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func validateURL(URL string) bool {
	_, err := url.Parse(URL)
	if err != nil {
		return false
	}
	return true
}

func validateHostname(hostname string) bool {
	addrs, err := net.LookupHost(hostname)

	// In some cases there is no error
	// but there are also no addresses
	if err != nil || len(addrs) < 1 {
		return false
	}
	return true
}

func main() {
	var (
		confAPI            = flag.String("api", "BUILTIN", "API entry point, for example https://www.example.com/api/")
		confGrade          = flag.Bool("grade", false, "Output only the hostname: grade")
		confHostcheck      = flag.Bool("hostcheck", false, "If true, host resolution failure will result in a fatal error.")
		confHostfile       = flag.String("hostfile", "", "File containing hosts to scan (one per line)")
		confIgnoreMismatch = flag.Bool("ignore-mismatch", false, "If true, certificate hostname mismatch does not stop assessment.")
		confInsecure       = flag.Bool("insecure", false, "Skip certificate validation. For use in development only. Do not use.")
		confJSONFlat       = flag.Bool("json-flat", false, "Output results in flattened JSON format")
		confQuiet          = flag.Bool("quiet", false, "Disable status messages (logging)")
		confUsecache       = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
		confMaxage         = flag.Int("maxage", 0, "Maximum acceptable age of cached results, in hours. A zero value is ignored.")
		confVerbosity      = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	)

	flag.Parse()

	logLevel = parseLogLevel(strings.ToLower(*confVerbosity))

	globalIgnoreMismatch = *confIgnoreMismatch

	if *confQuiet {
		logLevel = LogNone
	}

	// We prefer cached results
	if *confUsecache {
		globalFromCache = true
		globalStartNew = false
	}

	if *confMaxage != 0 {
		globalMaxAge = *confMaxage
	}

	// Verify that the API entry point is a URL.
	if *confAPI != "BUILTIN" {
		apiLocation = *confAPI
	}

	if validateURL(apiLocation) == false {
		log.Fatalf("[ERROR] Invalid API URL: %v", apiLocation)
	}

	var hostnames []string

	if *confHostfile != "" {
		// Open file, and read it
		var err error
		hostnames, err = readLines(confHostfile)
		if err != nil {
			log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
		}

	} else {
		// Read hostnames from the rest of the args
		hostnames = flag.Args()
	}

	if *confHostcheck {
		// Validate all hostnames before we attempt to test them. At least
		// one hostname is required.
		for _, host := range hostnames {
			if validateHostname(host) == false {
				log.Fatalf("[ERROR] Invalid hostname: %v", host)
			}
		}
	}

	if *confInsecure {
		globalInsecure = *confInsecure
	}

	hp := NewHostProvider(hostnames)
	manager := NewManager(hp)

	// Respond to events until all the work is done.
	for {
		_, running := <-manager.FrontendEventChannel
		if running == false {
			var results []byte
			var err error

			if *confGrade {
				// Just the grade(s). We use flatten and RAW
				/*
					"endpoints.0.grade": "A"
					"host": "testing.spatialkey.com"
				*/
				for i := range manager.results.responses {
					results := []byte(manager.results.responses[i])

					name := ""
					grade := ""

					flattened := flattenAndFormatJSON(results)

					for _, fval := range *flattened {
						if strings.HasPrefix(fval, "\"host\"") {
							// hostname
							parts := strings.Split(fval, ": ")
							name = strings.TrimSuffix(parts[1], "\n")
							if grade != "" {
								break
							}
						} else if strings.HasPrefix(fval, "\"endpoints.0.grade\"") {
							// grade
							parts := strings.Split(fval, ": ")
							grade = strings.TrimSuffix(parts[1], "\n")
							if name != "" {
								break
							}
						}
					}
					if grade != "" && name != "" {
						fmt.Println(name + ": " + grade)
					}
				}
			} else if *confJSONFlat {
				// Flat JSON and RAW

				for i := range manager.results.responses {
					results := []byte(manager.results.responses[i])

					flattened := flattenAndFormatJSON(results)

					// Print the flattened data
					fmt.Println(*flattened)
				}
			} else {
				// Raw (non-Go-mangled) JSON output

				fmt.Println("[")
				for i := range manager.results.responses {
					results := manager.results.responses[i]

					if i > 0 {
						fmt.Println(",")
					}
					fmt.Println(results)
				}
				fmt.Println("]")
			}

			if err != nil {
				log.Fatalf("[ERROR] Output to JSON failed: %v", err)
			}

			fmt.Println(string(results))

			if logLevel >= LogInfo {
				log.Println("[INFO] All assessments complete; shutting down")
			}

			return
		}
	}
}
