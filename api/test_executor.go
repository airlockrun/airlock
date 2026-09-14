package api

import (
	"io"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/integrations"
)

func testExecutorHandler(svc *integrations.TestExecutors) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ic, ok := integrationContextFromRequest(r)
		if !ok {
			writeServiceError(w, service.ErrUnauthorized, "test executor authentication failed")
			return
		}
		if r.Header.Get("Content-Type") != wire.TestExecutorContentType {
			http.Error(w, "test executor requires framed transport", http.StatusUnsupportedMediaType)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil && r.ProtoMajor != 2 {
			http.Error(w, "full-duplex transport unavailable", http.StatusInternalServerError)
			return
		}
		stream, err := svc.Open(r.Context(), ic.principal, ic.agentID)
		if err != nil {
			writeServiceError(w, err, "test executor provisioning failed")
			return
		}
		defer stream.Close()
		// Admit the streaming body only after provisioning succeeds. Rejections
		// can return without waiting for the client's first executor frame.
		if r.Header.Get("Expect") == "100-continue" {
			w.WriteHeader(http.StatusContinue)
		}
		w.Header().Set("Content-Type", wire.TestExecutorContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(stream, r.Body)
			_ = stream.Close()
		}()
		_, _ = io.Copy(executorFlushWriter{w, controller}, stream)
		_ = stream.Close()
		_ = controller.SetReadDeadline(time.Now())
		_ = r.Body.Close()
		<-done
	}
}

type executorFlushWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func (w executorFlushWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}
