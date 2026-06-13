package jsonapi

import "net/http"

var (
	writeJSON      = func(w http.ResponseWriter, status int, v any) {}
	writeJSONError = func(w http.ResponseWriter, status int, msg string) {}
	readJSON       = func(r *http.Request, v any) error { return nil }
)

func badJSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, nil)       // want `writeJSON in api/.*`
	writeJSONError(w, 500, "no") // want `writeJSONError in api/.*`
	var body any
	_ = readJSON(r, &body) // want `readJSON in api/.*`
}

func allowedJSON(w http.ResponseWriter) {
	// airlockvet:allow-writejson reason: legacy OAuth endpoint stays JSON
	writeJSON(w, 200, nil)
}
