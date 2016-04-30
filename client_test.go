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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

	var endpoints = []struct {
		url    string
		status int
	}{
		{"https://www.example.com/", http.StatusInternalServerError},
		{"https://www.fakemadeupexample2415.com/", http.StatusBadRequest},
		{ts.URL, http.StatusOK},
	}

	for _, ep := range endpoints {
		client := pararest.New(ep.url, secretKey.Bytes())
		resp := client.Post(testPayload, "/test")
		if resp.StatusCode != ep.status {
			t.Errorf("POST fail. Expected %d. Got: %d - %s", ep.status, resp.StatusCode, resp.Error)
		}
	}

}

func HandlePost(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	method := strings.ToUpper(req.Method)
	if method != "POST" {
		msg := fmt.Sprintf("Expected method POST, received %v", method)
		w.Write(errorResponse(msg, http.StatusBadRequest))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	method = strings.ToUpper(req.Header.Get(pararest.HeaderMethod))
	if method != "POST" {
		msg := fmt.Sprintf("Expected custom header method POST, received %v", method)
		w.Write(errorResponse(msg, http.StatusBadRequest))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := validateSignature(req)
	if err != nil {
		msg := fmt.Sprintf("Minion signature validation failed: %s", err)
		w.Write(errorResponse(msg, http.StatusUnauthorized))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, `{}`)
}

func errorResponse(msg string, code int) []byte {
	body := map[string]interface{}{
		"error":       msg,
		"status_code": code,
	}

	j, _ := json.Marshal(body)
	return j

}

func validateSignature(req *http.Request) error {
	var payload string
	for _, header := range pararest.CanonicalHeaders {
		payload += fmt.Sprintf("%s:%s\n", header, req.Header.Get(header))
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
		return fmt.Errorf("Did not receive valid %s.\nExpected: - %s -\nReceived: - %s -\n",
			pararest.HeaderAuthRequest,
			testHash,
			expectedHash)
	}

	return nil
}
