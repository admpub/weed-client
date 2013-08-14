/*
Copyright 2013 Tamás Gulácsi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package weedS3

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// {"count":1,"fid":"3,01637037d6","url":"127.0.0.1:8080","publicUrl":"localhost:8080"}
type weedAssignResponse struct {
	Count     int    `json:"count"`
	Fid       string `json:"fid"`
	URL       string `json:"url"`
	PublicURL string `json:"publicUrl"`
}

type weedLookupResponse struct {
	Locations []wmLocation `json:"locations"`
}

type wmLocation struct {
	PublicURL string `json:"publicUrl"`
	URL       string `json:"url"`
}

var client = &http.Client{
	Transport: &http.Transport{
		DisableKeepAlives: false, DisableCompression: false,
		MaxIdleConnsPerHost: 128}}

type weedMaster string

func newWeedMaster(url string) weedMaster {
	return weedMaster(url)
}

func (wm weedMaster) URL() string {
	return string(wm)
}

func (wm weedMaster) assignFid() (resp weedAssignResponse, err error) {
	err = masterGet(&resp, wm.URL()+"/dir/assign")
	if err == nil && resp.Fid == "" {
		err = errors.New("no file id!")
	}
	return
}

func (wm weedMaster) getFidURL(fid string) (url string, err error) {
	var vid string
	if i := strings.Index(fid, ","); i > 0 {
		vid = fid[:i]
	} else {
		vid = fid
	}
	var resp weedLookupResponse
	e := masterGet(&resp, wm.URL()+"/dir/lookup?volumeId="+vid)
	if e == nil && (resp.Locations == nil || len(resp.Locations) == 0 || resp.Locations[0].PublicURL == "") {
		e = fmt.Errorf("no public url for %s (resp=%s)", vid, resp)
	}
	if e != nil {
		err = e
		return
	}
	return resp.Locations[0].PublicURL + "/" + fid, nil
}

func masterGet(resp interface{}, url string) (err error) {
	r, e := getURL(url, "")
	if r != nil {
		defer r.Close()
	}
	if e != nil {
		err = fmt.Errorf("error getting %s: %s", url, e)
		return
	}
	//read JSON
	dec := json.NewDecoder(r)
	if err = dec.Decode(resp); err != nil {
		err = fmt.Errorf("error decoding response: %s", err)
	}
	return
}

// Upload uploads the payload
func (wm weedMaster) upload(resp weedAssignResponse, filename, contentType string, body io.Reader) (url string, err error) {
	url = "http://" + resp.PublicURL + "/" + resp.Fid
	var respBody []byte
	var e error
	for i := 0; i < 3; i++ {
		respBody, e = post(url, filename, contentType, body)
		if e != nil {
			log.Println(e)
			err = fmt.Errorf("error POSTing to %s: %s", url, e)
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}
	log.Printf("POST %s response: %s", url, respBody)

	return
}

func (wm weedMaster) download(fid string) (io.ReadCloser, error) {
	url, err := wm.getFidURL(fid)
	if err != nil {
		return nil, err
	}
	return getURL(url, "")
}

func (wm weedMaster) delete(fid string) error {
	url, err := wm.getFidURL(fid)
	if err != nil {
		return err
	}
	body, err := getURL(url, "DELETE")
	if body != nil {
		body.Close()
	}
	return err
}

// GetURL GETs the url, returns the body reader
func getURL(url, method string) (io.ReadCloser, error) {
	var (
		err  error
		req  *http.Request
		resp *http.Response
		msg  string
	)
	if url[0] == byte(':') {
		url = "http://localhost" + url
	} else if !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
		url = "http://" + url
	}
	for i := 0; i < 10; i++ {
		msg = ""
		if method == "" {
			method = "GET"
		}
		if method == "GET" {
			resp, err = client.Get(url)
		} else {
			req, err = http.NewRequest(method, url, nil)
			if err != nil {
				return nil, fmt.Errorf("error creating %s request for %s: %s",
					method, url, err)
			}
			resp, err = client.Do(req)
		}
		if resp == nil {
			// return nil, fmt.Errorf("nil response for %s!", url)
			msg = fmt.Sprintf("nil response for %s %s!", method, url)
		} else {
			if err == nil {
				if 200 <= resp.StatusCode && resp.StatusCode <= 299 {
					return resp.Body, nil
				}
				msg = fmt.Sprintf("STATUS=%s (%s)", resp.Status, url)
			} else {
				// dumpResponse(resp, true)
				msg = fmt.Sprintf("error with http.%s(%s): %s", method, url, err)
			}
		}
		log.Println(msg)
		time.Sleep(1 * time.Second)
	}
	return nil, errors.New(msg)
}

// post POSTs the payload to the url
func post(url, filename, contentType string, body io.Reader) (respBody []byte, err error) {
	reqbuf := bytes.NewBuffer(nil)
	formDataContentType, n, e := encodePayload(reqbuf, body, filename, contentType)
	if e != nil {
		err = e
		return
	}
	if n == 0 {
		err = errors.New("zero length encoded payload!")
		return
	}
	var (
		req  *http.Request
		resp *http.Response
	)
	req, e = http.NewRequest("POST", url, bytes.NewReader(reqbuf.Bytes()))
	if e != nil {
		err = fmt.Errorf("error creating POST to %s: %s", url, e)
		return
	}
	// log.Printf("CL=%d n=%d size=%d", req.ContentLength, n, len(reqbuf.Bytes()))
	req.ContentLength = int64(len(reqbuf.Bytes()))
	req.Header.Set("MIME-Version", "1.0")
	req.Header.Set("Content-Type", formDataContentType)
	//req.Header.Set("Accept-Encoding", "ident")

	for i := 0; i < 10; i++ {
		log.Printf("calling %s %s %s CL=%d n=%d", req.Method, req.URL, req.Header,
			req.ContentLength, len(reqbuf.Bytes()))
		log.Printf("req=%q", reqbuf.Bytes())
		resp, e = client.Do(req)
		if e == nil {
			break
		}
		log.Printf("POST error: %s", e)
		time.Sleep(1 * time.Second)
	}
	if e != nil {
		err = fmt.Errorf("error pOSTing %+v: %s", req, e)
		return
	}
	if resp != nil {
		req = resp.Request
	}
	if resp == nil || resp.Body == nil {
		err = fmt.Errorf("nil response")
		return
	}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		respBody = make([]byte, resp.ContentLength)
		if length, e := io.ReadFull(resp.Body, respBody); e == nil && length > 0 {
			respBody = respBody[:length]
		} else {
			err = fmt.Errorf("error reading response %d body: %s", length, e)
			return
		}
	} else if resp.ContentLength < 0 {
		respBody, e = ioutil.ReadAll(resp.Body)
	}
	if e != nil {
		err = fmt.Errorf("error reading response body: %s", e)
	}

	if !(200 <= resp.StatusCode && resp.StatusCode <= 299) {
		err = fmt.Errorf("errorcode=%d message=%s", resp.StatusCode, respBody)
		return
	}
	log.Printf("POST %s => [%d] %v %s", url, resp.StatusCode, resp.Header, respBody)
	if !bytes.HasPrefix(respBody, []byte(`{"size":`)) {
		err = fmt.Errorf("no size in response %s", respBody)
	}

	return
}

func encodePayload(w io.Writer, r io.Reader, filename, contentType string) (string, int64, error) {
	mw := multipart.NewWriter(w)
	defer mw.Close()
	log.Printf("fn=%q", filename)
	fw, err := createFormFile(mw, "file", filename, contentType)
	// fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		log.Panicf("cannot create FormFile: %s", err)
	}
	n, err := io.Copy(fw, r)
	return mw.FormDataContentType(), n, err
}

// createFormFile creates a form file
func createFormFile(w *multipart.Writer, fieldname, filename, contentType string) (io.Writer, error) {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			escapeQuotes(fieldname), escapeQuotes(filename)))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return w.CreatePart(h)
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}
