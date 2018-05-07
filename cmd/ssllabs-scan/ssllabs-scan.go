package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	scan "github.com/ssllabs/ssllabs-scan"
)

var USER_AGENT = "ssllabs-scan v1.4.0 (stable $Id$)"

var logLevel = scan.LOG_NOTICE

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
		log.Fatalf("[ERROR] Reconstitution of JSON failed: %v", err)
	}

	// Flatten the JSON structure, recursively
	flattenJSON(mappedJSON, "", &flattened)

	// Make a sorted index, so we can print keys in order
	kIndex := make([]string, len(flattened))
	ki := 0
	for key, _ := range flattened {
		kIndex[ki] = key
		ki++
	}
	sort.Strings(kIndex)

	// Ordered flattened data
	var flatStrings []string
	for _, value := range kIndex {
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
		var line = strings.TrimSpace(scanner.Text())
		if (!strings.HasPrefix(line, "#")) && (line != "") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func validateURL(URL string) bool {
	_, err := url.Parse(URL)
	if err != nil {
		return false
	} else {
		return true
	}
}

func validateHostname(hostname string) bool {
	addrs, err := net.LookupHost(hostname)

	// In some cases there is no error
	// but there are also no addresses
	if err != nil || len(addrs) < 1 {
		return false
	} else {
		return true
	}
}

func main() {
	var conf_api = flag.String("api", "BUILTIN", "API entry point, for example https://www.example.com/api/")
	var conf_grade = flag.Bool("grade", false, "Output only the hostname: grade")
	var conf_hostcheck = flag.Bool("hostcheck", false, "If true, host resolution failure will result in a fatal error.")
	var conf_hostfile = flag.String("hostfile", "", "File containing hosts to scan (one per line)")
	var conf_ignore_mismatch = flag.Bool("ignore-mismatch", false, "If true, certificate hostname mismatch does not stop assessment.")
	var conf_insecure = flag.Bool("insecure", false, "Skip certificate validation. For use in development only. Do not use.")
	var conf_json_flat = flag.Bool("json-flat", false, "Output results in flattened JSON format")
	var conf_quiet = flag.Bool("quiet", false, "Disable status messages (logging)")
	var conf_usecache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var conf_maxage = flag.Int("maxage", 0, "Maximum acceptable age of cached results, in hours. A zero value is ignored.")
	var conf_verbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")

	flag.Parse()

	if *conf_version {
		fmt.Println(USER_AGENT)
		fmt.Println("API location: " + *conf_api)
		return
	}

	logLevel = scan.ParseLogLevel(strings.ToLower(*conf_verbosity))

	scan.IgnoreMismatch(*conf_ignore_mismatch)

	if *conf_quiet {
		logLevel = scan.LOG_NONE
	}

	// We prefer cached results
	scan.UseCache(*conf_usecache)

	if *conf_maxage != 0 {
		scan.SetMaxAge(*conf_maxage)
	}

	// Verify that the API entry point is a URL.
	if *conf_api != "BUILTIN" {
		if validateURL(*conf_api) == false {
			log.Fatalf("[ERROR] Invalid API URL: %v", *conf_api)
		}
		scan.SetAPILocation(*conf_api)
	}

	var hostnames []string

	if *conf_hostfile != "" {
		// Open file, and read it
		var err error
		hostnames, err = readLines(conf_hostfile)
		if err != nil {
			log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
		}

	} else {
		// Read hostnames from the rest of the args
		hostnames = flag.Args()
	}

	if *conf_hostcheck {
		// Validate all hostnames before we attempt to test them. At least
		// one hostname is required.
		for _, host := range hostnames {
			if validateHostname(host) == false {
				log.Fatalf("[ERROR] Invalid hostname: %v", host)
			}
		}
	}

	scan.AllowInsecure(*conf_insecure)

	hp := scan.NewHostProvider(hostnames)
	manager := scan.NewManager(hp)

	// Respond to events until all the work is done.
	for {
		_, running := <-manager.FrontendEventChannel
		if running == false {
			var results []byte
			var err error

			if hp.StartingLen == 0 {
				return
			}

			if *conf_grade {
				// Just the grade(s). We use flatten and RAW
				/*
					"endpoints.0.grade": "A"
					"host": "testing.spatialkey.com"
				*/
				for i := range manager.Results.Responses {
					results := []byte(manager.Results.Responses[i])

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
			} else if *conf_json_flat {
				// Flat JSON and RAW

				for i := range manager.Results.Responses {
					results := []byte(manager.Results.Responses[i])

					flattened := flattenAndFormatJSON(results)

					// Print the flattened data
					fmt.Println(*flattened)
				}
			} else {
				// Raw (non-Go-mangled) JSON output

				fmt.Println("[")
				for i := range manager.Results.Responses {
					results := manager.Results.Responses[i]

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

			if logLevel >= scan.LOG_INFO {
				log.Println("[INFO] All assessments complete; shutting down")
			}

			return
		}
	}
}
