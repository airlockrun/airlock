package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/sol/webfetch"
)

func (h *Service) RuntimeHTTP(ctx context.Context, scope wire.RuntimeContext, input wire.HTTPRequest) (wire.HTTPResponse, error) {
	var output wire.HTTPResponse
	var err error
	scope, err = h.admittedContext(ctx, scope)
	if err != nil {
		return output, err
	}
	url, err := h.httpNetwork.ParseURL(input.URL)
	if err != nil {
		return output, err
	}
	method := input.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, url.String(), strings.NewReader(input.Body))
	if err != nil {
		return output, err
	}
	request.Header.Set("User-Agent", webfetch.UserAgent)
	for key, value := range input.Headers {
		request.Header.Set(key, value)
	}
	timeout := input.Timeout
	if timeout <= 0 {
		timeout = HttpDefaultTimeout
	}
	if timeout > HttpMaxTimeout {
		timeout = HttpMaxTimeout
	}
	response, err := h.httpNetwork.Client(time.Duration(timeout) * time.Second).Do(request)
	if err != nil {
		return output, err
	}
	defer response.Body.Close()
	output.Status, output.Headers, output.ContentType = response.StatusCode, CurateHeaders(response.Header, input.AllHeaders), response.Header.Get("Content-Type")
	if input.SaveAs != "" {
		file, err := h.files.ResolveForRuntime(ctx, scope, input.SaveAs, agentstorage.OperationWrite)
		if err != nil {
			return output, err
		}
		output.Size, output.BodyPreview, err = StreamSaveToS3(ctx, h.s3, file.S3Key, response.Body, IsBinaryContentType(output.ContentType))
		output.SavedTo = file.Relative
		return output, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, HttpMaxHTMLBytes+1))
	if err != nil {
		return output, err
	}
	if len(data) > HttpMaxHTMLBytes {
		return output, errors.New("HTTP response too large; specify saveAs")
	}
	if !input.Raw && IsHTMLContentType(output.ContentType) {
		data = []byte(webfetch.ConvertHTMLToMarkdown(string(data)))
		output.Note = "Body converted from HTML to markdown."
	}
	output.Size = len(data)
	if IsBinaryContentType(output.ContentType) || len(data) > HttpAutoSaveThreshold {
		key := GenerateAutoSaveKey(input.URL, output.ContentType, response.Header.Get("Content-Disposition"))
		file, err := h.files.ResolveForRuntime(ctx, scope, key, agentstorage.OperationWrite)
		if err != nil {
			return output, err
		}
		if err := h.s3.PutObject(ctx, file.S3Key, strings.NewReader(string(data)), int64(len(data))); err != nil {
			return output, err
		}
		output.SavedTo = file.Relative
		if !IsBinaryContentType(output.ContentType) {
			output.BodyPreview = PreviewText(data)
		}
	} else {
		output.Body = string(data)
	}
	return output, nil
}
