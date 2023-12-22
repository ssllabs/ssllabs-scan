//go:build go1.3

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

// work in progress
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
)

type RegisterRequest struct {
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
}

type ErrorResponse struct {
	Errors []struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"errors"`
}

func main() {
	// Define command-line flags
	firstName := flag.String("firstName", "", "First name")
	lastName := flag.String("lastName", "", "Last name")
	email := flag.String("email", "", "Email")
	organization := flag.String("organization", "", "Organization")
	registerApiUrl := flag.String("registerApiUrl", "https://api.ssllabs.com/api/v4/register", "API endpoint URL")
	flag.Parse()

	// Validate required flags
	if *firstName == "" || *lastName == "" || *email == "" || *organization == "" {
		fmt.Println("All flags (firstName, lastName, email, organization) are required.")
		return
	}

	// Create RegisterRequest instance
	requestData := RegisterRequest{
		FirstName:    *firstName,
		LastName:     *lastName,
		Email:        *email,
		Organization: *organization,
	}

	// Convert data to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}

	// Make the HTTP POST request
	resp, err := http.Post(*registerApiUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		// Handle error response
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			fmt.Println("Error decoding error response:", err)
			return
		}

		fmt.Println("API Error Response:")
		for _, e := range errorResponse.Errors {
			fmt.Printf("Email: %s, Field: %s, Message: %s\n", requestData.Email, e.Field, e.Message)
		}
		return
	}

	// Print the response body
	var responseMap map[string]interface{}
	err = json.Unmarshal(body, &responseMap)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	fmt.Printf("API Response: Status - %s, Message - %s\n", responseMap["status"], responseMap["message"])
}
