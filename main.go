/**
@author       MouMeng <iamoumeng@aliyun.com>
@datetime     2023/5/23 9:07
*/

package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
	Timeout: 5 * time.Second, // 超时时间
	Transport: &http.Transport{
		MaxIdleConns:       100,              // 最大空闲连接数
		IdleConnTimeout:    90 * time.Second, // 空闲连接超时时间
		DisableCompression: true,             // 禁用压缩
	},
}

func handleError(err error, msg string) {
	if err != nil {
		t := time.Now()
		fmt.Printf("[%d-%d-%d %d:%d:%d]:"+"%s %v\n", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Minute(), msg, err)
	}
}

func main() {

	fingerItems := loadFingerItems()
	fmt.Println("__        ___           _    ____               \n\\ \\      / / |__   __ _| |_ / ___|_ __ ___  ___ \n \\ \\ /\\ / /| '_ \\ / _` | __| |   | '_ ` _ \\/ __|\n  \\ V  V / | | | | (_| | |_| |___| | | | | \\__ \\\n   \\_/\\_/  |_| |_|\\__,_|\\__|\\____|_| |_| |_|___/\n_________________________________________________")
	url := "https://www.lnsec.cn/"
	cmsType := identifyCMS(url, fingerItems)
	if cmsType != "" {
		fmt.Printf(cmsType)
	} else {
		handleError(errors.New(" "), "无法识别目标站点CMS")
	}
}

func loadFingerItems() []FingerItem {
	content, err := os.ReadFile("./res/finger.json")
	handleError(err, "无法读取配置文件 finger.json")

	var fingerItems []FingerItem
	err = json.Unmarshal(content, &fingerItems)
	handleError(err, "无法解析配置文件 finger.json")

	return fingerItems
}

func identifyCMS(url string, fingerItems []FingerItem) string {

	resp, err := httpClient.Get(url)
	tempResp := resp
	if err != nil {
		handleError(err, "无法连接到目标站点")
		return ""
	}

	respIco, err := httpClient.Get(url + "/favicon.ico")
	if err != nil {
		handleError(err, "无法连接到目标站点")
		return ""
	}

	hashString := ""
	if err == nil && resp.StatusCode == 200 {
		bytes, _ := io.ReadAll(respIco.Body)
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
			handleError(err, "请求失败 :"+item.Path)
		} else {
			resp = tempResp
		}

		if len(item.Headers) > 0 {
			if !HeadersMatch(resp.Header, item.Headers) {
				continue
			}
		}

		if len(item.Keyword) > 0 {
			if !KeywordsMatch(string(body), item.Keyword) {
				continue
			}
		}

		if len(item.FaviconHash) > 0 {
			if !FaviconHashMatch(hashString, item.FaviconHash) {
				continue
			}
		}

		return item.Name
	}

	return ""
}
