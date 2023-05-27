/**
@author       MouMeng <iamoumeng@aliyun.com>
@datetime     2023/5/27 11:24
*/

package main

import (
	"net/http"
	"strings"
)

func HeadersMatch(headers http.Header, expected map[string]string) bool {
	for k, v := range expected {
		value := headers.Get(k)
		if value != "" && value == v {
			continue
		}
		return false
	}
	return true
}

func KeywordsMatch(body string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(body, keyword) {
			continue
		}
		return false
	}
	return true
}

func FaviconHashMatch(hashString string, expected []string) bool {
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
