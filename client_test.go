/* Pararest
 * Copyright (C) 2016 Miguel Moll
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

package pararest_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/satori/go.uuid"

	"dynastic.ninja/paranoid/pararest"
)

var secretKey = uuid.NewV4()
var testPayload = `{"username":"testuser", "password":"testpass"}`

func TestClientPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(HandlePost))
	defer ts.Close()

	//URL, _ := url.Parse("http://www.goti85.com")
	URL, _ := url.Parse(ts.URL)
	client := pararest.New(URL, secretKey.Bytes())
	code, msg := client.Post(testPayload, "/test")
	if code != http.StatusOK {
		t.Errorf("POST fail. Expected 200. Got: %d - %s ", code, msg)
	}
}

func HandlePost(w http.ResponseWriter, req *http.Request) {
	method := strings.ToUpper(req.Method)
	if method != "POST" {
		msg := fmt.Sprintf("Expected method POST, received %v", method)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	method = strings.ToUpper(req.Header.Get(pararest.HeaderMethod))
	if method != "POST" {
		msg := fmt.Sprintf("Expected custom header method POST, received %v", method)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	err := validateSignature(req)
	if err != nil {
		msg := fmt.Sprintf("Minion signature validation failed: %s", err)
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}
}

func validateSignature(req *http.Request) error {
	var payload string
	for _, header := range pararest.CanonicalHeaders {
		payload += fmt.Sprintf("%s:%s", header, req.Header.Get(header))
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body: %s\n", err)
	}
	payload += string(body)

	mac := hmac.New(sha256.New, secretKey.Bytes())
	mac.Write([]byte(payload))

	testHash := fmt.Sprintf("%x", mac.Sum(nil))
	expectedHash := req.Header.Get(pararest.HeaderAuthRequest)

	if testHash != expectedHash {
		return fmt.Errorf("Did not receive valid %s.\nExpected:-%s-\nReceived:-%s-\n",
			pararest.HeaderAuthRequest,
			testHash,
			expectedHash)
	}

	return nil
}
