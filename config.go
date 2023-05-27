/**
@author       MouMeng <iamoumeng@aliyun.com>
@datetime     2023/5/27 11:13
*/

package main

import (
	"net/http"
	"time"
)

var HttpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:       100,              // 最大空闲连接数
		IdleConnTimeout:    90 * time.Second, // 空闲连接超时时间
		DisableCompression: true,             // 禁用压缩
	},
}
