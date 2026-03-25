//go:build !android && !ios

package ui

import "os"

// Run is the application entry point for desktop platforms (macOS, Windows,
// Linux). If a known CLI sub-command is present on os.Args, the text-based
// CLI is used; otherwise the Fyne GUI is launched.
func Run() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "create", "watch", "list", "ls", "decrypt", "get", "delete", "rm",
			"help", "-h", "--help":
			runCLI()
			return
		}
	}
	runGUI()
}
