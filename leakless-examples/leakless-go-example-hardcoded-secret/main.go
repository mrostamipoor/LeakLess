package main



import (
	"fmt"
	"net/http"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
)

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		// Get config value `message` defined in spin.toml.

		

		var secretKey = "secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" 

		headerVal := r.Header.Get("api-key")

		// Compare the config value with the header value
		if secretKey == headerVal {
			// If they are equal, return HTTP 200 and a confirmation message
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Values are equal.\nConfig value: %s\nHeader value: %s\n", secretKey, headerVal)
		} else {
			// If they are not equal, return HTTP 401 and an error message
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Access denied: Values do not match.\nConfig value: %s\nHeader value: %s\n", secretKey, headerVal)
		}
	})
}

func main() {}

