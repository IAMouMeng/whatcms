package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type FingerItem struct {
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestData    string            `json:"request_data"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Keyword        []string          `json:"keyword"`
	FaviconHash    []string          `json:"favicon_hash"`
}

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:       100,              // 最大空闲连接数
		IdleConnTimeout:    90 * time.Second, // 空闲连接超时时间
		DisableCompression: true,             // 禁用压缩
	},
}

func handleError(err error, msg string) {
	if err != nil {
		fmt.Printf("%s: %v\n", msg, err)
		panic(err)
	}
}

func main() {

	fingerItems := loadFingerItems()

	url := "https://www.lnsec.cn/"
	cmsType := identifyCMS(url, fingerItems)
	if cmsType != "" {
		fmt.Printf(cmsType)
	} else {
		fmt.Println("无法识别")
	}
}

func loadFingerItems() []FingerItem {
	content, err := ioutil.ReadFile("res/finger.json")
	handleError(err, "Failed to read finger.json")

	var fingerItems []FingerItem
	err = json.Unmarshal(content, &fingerItems)
	handleError(err, "Failed to unmarshal fingerItems")

	return fingerItems
}

func identifyCMS(url string, fingerItems []FingerItem) string {

	resp, err := httpClient.Get(url)
	tempResp := resp
	handleError(err, "Failed to execute http.Get")
	defer resp.Body.Close()

	respIco, err := httpClient.Get(url + "/favicon.ico")
	handleError(err, "Failed to execute http.Get")
	defer respIco.Body.Close()

	hashString := ""
	if respIco.StatusCode == 200 {
		bytes, err := io.ReadAll(respIco.Body)
		handleError(err, "Failed to execute io")
		hash := md5.Sum(bytes)
		hashString = hex.EncodeToString(hash[:])
	}

	body, err := io.ReadAll(resp.Body)
	handleError(err, "Failed to read response body")

	for _, item := range fingerItems {

		if item.StatusCode != 0 && resp.StatusCode != item.StatusCode {
			continue
		}

		if item.Path != "/" || len(item.RequestHeaders) > 0 || item.RequestData != "" || item.RequestMethod != "get" {
			req, _ := http.NewRequest(item.RequestMethod, url+item.Path, strings.NewReader(item.RequestData))
			for key, value := range item.Headers {
				req.Header.Add(key, value)
			}
			resp, err = httpClient.Do(req)
			handleError(err, "Failed to execute http.Get")
			resp.Body.Close()
		} else {
			resp = tempResp
		}

		if len(item.Headers) > 0 {
			if !headersMatch(resp.Header, item.Headers) {
				continue
			}
		}

		if len(item.Keyword) > 0 {
			if !keywordsMatch(string(body), item.Keyword) {
				continue
			}
		}

		if len(item.FaviconHash) > 0 {
			if !faviconHashMatch(hashString, item.FaviconHash) {
				continue
			}
		}

		return item.Name
	}

	return ""
}

func headersMatch(headers http.Header, expected map[string]string) bool {
	for k, v := range expected {
		value := headers.Get(k)
		if value != "" && value == v {
			continue
		}
		return false
	}
	return true
}

func keywordsMatch(body string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(body, keyword) {
			continue
		}
		return false
	}
	return true
}

func faviconHashMatch(hashString string, expected []string) bool {
	if hashString == "" {
		return false
	}
	for _, hash := range expected {
		if hashString == hash {
			continue
		}
		return false
	}
	return true
}
