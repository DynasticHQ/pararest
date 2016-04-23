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
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"gopkg.in/resty.v0"
)

type Payload interface{}

type Client struct {
	URL       *url.URL
	SecretKey []byte

	r *resty.Request
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

// New creates a RestClient.
func New(url *url.URL, secretKey []byte) *Client {
	c := &Client{
		URL:       url,
		SecretKey: secretKey,
		r:         resty.R().SetHeader("Content-Type", "application/json"),
	}
	return c
}

// Post the payload to the URL and endpoint specified.
func (c *Client) Post(p Payload, endpoint string) (int, string) {

	c.URL.Path = path.Join(c.URL.Path, endpoint)
	c.r.SetHeaders(map[string]string{
		HeaderTimestamp: time.Now().UTC().Format(time.RFC3339),
		HeaderHost:      c.URL.Host,
		HeaderPath:      c.URL.Path,
		HeaderMethod:    "POST",
	})

	c.r.SetBody(p)
	c.signRequest()

	resp, err := c.r.Post(c.URL.String())
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}
	return resp.StatusCode(), resp.String()
}

// signRequest signs the request with the canoical headers.
func (c *Client) signRequest() {
	var payload string
	for _, header := range CanonicalHeaders {
		payload += fmt.Sprintf("%s:%s\n", header, c.r.Header.Get(header))
	}

	ps, ok := c.r.Body.(string)
	if !ok {
		// TODO(miguelmoll): Make sure to return and handle errors.
		return
	}
	payload += ps

	mac := hmac.New(sha256.New, c.SecretKey)
	mac.Write([]byte(payload))

	c.r.SetHeader(HeaderAuthRequest, fmt.Sprintf("%x", mac.Sum(nil)))
}
