package main

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	_ "github.com/goccy/wasi-go/ext/wasip1"
)

//go:wasmexport testHTTP
func testHTTP() {
	resp, err := http.Get("https://example.com/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if len(body) == 0 {
		panic("failed to get body")
	}
}

//go:wasmexport testExec
func testExec() {
	out, err := exec.Command("echo", "1").CombinedOutput()
	if err != nil {
		panic(err)
	}
	if strings.TrimSpace(string(out)) != "1" {
		panic(fmt.Sprintf("failed to capture command output: %q", out))
	}
}

func main() {}
