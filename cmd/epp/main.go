package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	specURL := flag.String("spec", "http://localhost:8080/spec", "gateway spec endpoint")
	method := flag.String("X", "GET", "HTTP method")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: epp [-X METHOD] [-spec URL] <path> [json-body]")
		os.Exit(2)
	}

	path := args[0]
	var body io.Reader
	if len(args) > 1 {
		body = strings.NewReader(args[1])
	}

	if *method != "GET" && len(args) <= 1 {
		fmt.Fprintln(os.Stderr, "warning: non-GET without body")
	}

	req, err := http.NewRequest(*method, "http://localhost:8080/api"+path, body)
	if err != nil {
		fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	switch *method {
	case "GET":
		// optional spec lookup mode
		if strings.HasPrefix(path, "--spec") {
			dumpSpec(*specURL)
			return
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP %d\n%s\n", resp.StatusCode, raw)
}

func dumpSpec(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	var spec json.RawMessage
	json.NewDecoder(resp.Body).Decode(&spec)
	pretty, _ := json.MarshalIndent(spec, "", "  ")
	fmt.Println(string(pretty))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
