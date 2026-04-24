package container

import (
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 2 * time.Second}

func httpGet(url string) (*http.Response, error) {
	return httpClient.Get(url)
}
