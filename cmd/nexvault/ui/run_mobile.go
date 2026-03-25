//go:build android || ios

package ui

// Run is the application entry point for Android and iOS.
// There is no CLI on mobile; the Fyne GUI is launched directly.
func Run() {
	runGUI()
}
