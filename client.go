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

package pararest

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"gopkg.in/resty.v0"
)

type MinionClient struct {
	URL       *url.URL
	SecretKey []byte

	rc *resty.Client
}

// Headers
const (
	HeaderAuthRequest = "X-PARA-AUTH-REQUEST" //
	HeaderTimestamp   = "X-PARA-TIMESTAMP"    // Timestamp of request in RFC3339 UTC format
	HeaderMethod      = "X-PARA-METHOD"       // GET, POST, etc
	HeaderPath        = "X-PARA-PATH"         // /path/to/api/call
	HeaderHost        = "X-PARA-HOST"         // api.example.com:8080
	HeaderQueryString = "X-PARA-QUERY"
)

var CanonicalHeaders = []string{
	// Order is important here!
	HeaderHost,
	HeaderPath,
	HeaderMethod,
	HeaderQueryString,
	HeaderTimestamp,
}

// New creates a MinionClient to issue API commands.
// u is the full URL. Example: https://www.example.com/
func New(u string, key []byte) *MinionClient {

	mc := &MinionClient{
		SecretKey: key,
		rc:        resty.New(),
	}

	_url, err := url.Parse(u)
	if err != nil {
		// TODO(miguelmoll): Don't like how this silently swallows the error.
		// It returns a client with out a URL leaving that to the caller. Fix this!
		return mc
	}

	mc.URL = _url

	// Only JSON is supported at this moment.
	mc.rc.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
		if resp.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			return errors.New("Invalid server Content-Type. Needs to be 'application/json; charset=utf-8'.")
		}
		return nil // if its success otherwise return error
	})

	return mc
}

// Post the payload to the URL and endpoint specified.
func (mc *MinionClient) Post(payload interface{}, endpoint string) ResponsePayload {

	var response ResponsePayload
	request := mc.newRequest()

	mc.URL.Path = path.Join(mc.URL.Path, endpoint)
	request.SetHeaders(map[string]string{
		HeaderTimestamp: time.Now().UTC().Format(time.RFC3339),
		HeaderHost:      mc.URL.Host,
		HeaderPath:      mc.URL.Path,
		HeaderMethod:    "POST",
	})

	request.SetBody(payload)
	signRequest(request, mc.SecretKey)

	resp, err := request.Post(mc.URL.String())
	if err != nil {

		// Ugly hack to check if the response is "empty". Response object can be "not nil" and empty.
		// Most likely client or network error. e.g dns lookup failed.
		if resp != nil && resp.String() != "" {
			response.StatusCode = resp.StatusCode()
		} else {
			response.StatusCode = http.StatusBadRequest
		}

		response.Error = err
		return response
	}

	return parseResponse(resp)
}

// Bootstrap kicks off minion registration with the server.
// Returns a minion secret for the bootstrapping minion.
func (mc *MinionClient) Bootstrap() BootstrapResponse {

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}

	payload := map[string]interface{}{
		"hostname": hostname,
	}

	return toBootstrapResponse(mc.Post(payload, "/bootstrap"))
}

func (mc *MinionClient) newRequest() *resty.Request {
	req := mc.rc.R()
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	return req
}

// signRequest signs the canoical headers of a request using the secretKey.
func signRequest(r *resty.Request, secretKey []byte) {
	var payload string
	for _, header := range CanonicalHeaders {
		payload += fmt.Sprintf("%s:%s\n", header, r.Header.Get(header))
	}

	ps, ok := r.Body.(string)
	if !ok {
		// TODO(miguelmoll): Make sure to return and handle errors.
		return
	}
	payload += ps

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(payload))

	r.SetHeader(HeaderAuthRequest, fmt.Sprintf("%x", mac.Sum(nil)))
}
