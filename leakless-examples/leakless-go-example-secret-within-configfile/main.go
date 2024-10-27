package main

import (
	"fmt"
	"net/http"

	"github.com/fermyon/spin/sdk/go/config"
	spinhttp "github.com/fermyon/spin/sdk/go/http"
)

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		// Get config value `message` defined in spin.toml.
		configVal, err := config.Get("api_key")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		headerVal := r.Header.Get("api-key")

		// Compare the config value with the header value
		if configVal == headerVal {
			// If they are equal, return HTTP 200 and a confirmation message
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Values are equal.\nConfig value: %s\nHeader value: %s\n", configVal, headerVal)
		} else {
			// If they are not equal, return HTTP 401 and an error message
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Access denied: Values do not match.\nConfig value: %s\nHeader value: %s\n", configVal, headerVal)
		}
	})
}

func main() {}
