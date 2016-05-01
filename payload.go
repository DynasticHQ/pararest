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
	"encoding/json"
	"fmt"
	"net/http"

	"gopkg.in/resty.v0"
)

type ResponsePayload struct {
	StatusCode int
	Error      error
	Data       map[string]interface{}
}

type BootstrapResponse struct {
	ResponsePayload
	MinionKey     []byte
	QueueUsername string
	QueuePassword string
}

func parseResponse(resp *resty.Response) ResponsePayload {
	var rp ResponsePayload

	rp.StatusCode = resp.StatusCode()

	err := json.Unmarshal(resp.Body(), &rp.Data)
	if err != nil {
		rp.Error = err
		rp.StatusCode = http.StatusInternalServerError
		return rp
	}

	if e, ok := rp.Data["error"]; ok {
		rp.Error = fmt.Errorf("%s", e)
	}

	return rp
}

func toBootstrapResponse(rp ResponsePayload) BootstrapResponse {
	var br BootstrapResponse

	return br
}
