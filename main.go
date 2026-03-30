//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gpoview/gpo"
	"gpoview/web"

	"golang.org/x/sys/windows"
)

func main() {
	if !amAdmin() {
		fmt.Println("Not running with admin privileges. Attempting to relaunch with elevation…")
		runMeElevated()
		return
	}

	port := flag.Int("port", 8080, "HTTP port to listen on")
	noBrowser := flag.Bool("no-browser", false, "Do not open the browser automatically")
	flag.Parse()

	log.Println("Collecting GPO data via gpresult…")
	start := time.Now()

	xmlData, fetchErr := gpo.Fetch()
	if fetchErr != nil {
		// Non-fatal: show the error in the UI but still start the server.
		log.Printf("Warning: gpresult returned an error: %v", fetchErr)
	}

	var report *gpo.Report
	if len(xmlData) > 0 {
		var parseErr error
		report, parseErr = gpo.Parse(xmlData)
		if parseErr != nil {
			log.Printf("Warning: failed to parse RSoP XML: %v", parseErr)
		}
	}

	if report == nil {
		report = &gpo.Report{
			GeneratedAt: time.Now(),
			FetchError:  fetchErr,
		}
	} else {
		report.FetchError = fetchErr
	}

	log.Printf("Data collected in %s", time.Since(start).Round(time.Millisecond))

	addr := fmt.Sprintf(":%d", *port)
	url := fmt.Sprintf("http://localhost:%d", *port)

	if !*noBrowser {
		// Open browser after a short delay so the server is ready.
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}

	log.Printf("GPO Viewer running at %s  (Ctrl+C to stop)", url)
	if err := web.StartServer(addr, report); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func amAdmin() bool {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	fmt.Printf("admin %v\n", elevated)
	return elevated
}
