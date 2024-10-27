package main
//go:generate go run encryptor/encryptor.go -- $GOFILE
import (
	"fmt"
	"net/http"
	"os"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
)
//#[LEAKLESS_SECRET]
const authToken = "LEAKLESS_RgJgLi/fe030H7s2hNq7uqRPJcd6oDc5NWwTcujbVJhbLZHbHLCf7Cp0XjY9Y9Ub_LEAKLESS"

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequest("GET", "http://0.0.0.0:5000/verify-key", nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
			return
		}
		req.Header.Add("Authorization", "Bearer "+authToken)

		resp, err := spinhttp.Send(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending request: %v\n", err)
			return
		}

		fmt.Fprintf(w, "Response Status: %s\n", resp.Status)
		fmt.Fprintf(w, "Response Headers: %v\n", resp.Header)
	})
}

func main() {}

