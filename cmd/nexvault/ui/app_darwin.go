//go:build darwin

// Package ui provides the native macOS AppKit interface for nexvault.
// The app lives entirely in the menu bar (no Dock icon). A padlock SF Symbol
// in the status item gives access to all vault operations through native macOS
// controls: NSAlert + NSSecureTextField for passwords, NSOpenPanel for folder
// selection, and an NSTableView panel for browsing and managing vault entries.
package ui

import (
"fmt"
"os"
"path/filepath"
"runtime"
"sort"
"strings"
"sync"
"time"

"github.com/progrium/darwinkit/helper/action"
"github.com/progrium/darwinkit/macos/appkit"
"github.com/progrium/darwinkit/macos/foundation"
"github.com/progrium/darwinkit/objc"
"github.com/progrium/darwinkit/dispatch"

"nexvault/internal/vault"
"nexvault/internal/watcher"
)

// ── State ────────────────────────────────────────────────────────────────────

type vaultApp struct {
app        appkit.Application
statusItem appkit.StatusItem

mu        sync.Mutex
session   *vault.Session // nil when locked
vaultPath string
dropPath  string
w         *watcher.Watcher
}

// ── Entry point ───────────────────────────────────────────────────────────────

// Run is the macOS native UI entry point (darwin only).
func Run() {
// The AppKit event loop must own the OS thread that called main().
runtime.LockOSThread()

a := appkit.Application_SharedApplication()
va := &vaultApp{app: a}

delegate := &appkit.ApplicationDelegate{}
delegate.SetApplicationWillFinishLaunching(func(foundation.Notification) {
va.setupMainMenu()
})
delegate.SetApplicationDidFinishLaunching(func(foundation.Notification) {
va.setupStatusItem()
// Suppress the Dock icon — we are a menu-bar-only agent.
a.SetActivationPolicy(appkit.ApplicationActivationPolicyProhibited)
})
// Keep the process alive after the entry browser window is closed.
delegate.SetApplicationShouldTerminateAfterLastWindowClosed(func(appkit.Application) bool {
return false
})

a.SetDelegate(delegate)
a.Run()
}

// ── Setup ─────────────────────────────────────────────────────────────────────

func (va *vaultApp) setupMainMenu() {
// A minimal menu bar is required so ⌘Q and clipboard shortcuts work.
bar := appkit.NewMenuWithTitle("")
va.app.SetMainMenu(bar)

appItem := appkit.NewMenuItemWithSelector("", "", objc.Selector{})
appMenu := appkit.NewMenuWithTitle("nexvault")
appMenu.AddItem(appkit.NewMenuItemWithAction("Quit nexvault", "q", func(objc.Object) {
va.shutdown()
va.app.Terminate(nil)
}))
appItem.SetSubmenu(appMenu)
bar.AddItem(appItem)
}

func (va *vaultApp) setupStatusItem() {
item := appkit.StatusBar_SystemStatusBar().StatusItemWithLength(appkit.VariableStatusItemLength)
objc.Retain(&item)
va.statusItem = item
va.setIcon(true)
va.rebuildMenu()
}

// ── Icon ─────────────────────────────────────────────────────────────────────

func (va *vaultApp) setIcon(locked bool) {
name := "lock.fill"
if !locked {
name = "lock.open.fill"
}
img := appkit.Image_ImageWithSystemSymbolNameAccessibilityDescription(name, "nexvault")
img.SetTemplate(true) // follows system accent colour and dark/light mode
va.statusItem.Button().SetImage(img)
}

// ── Menu ─────────────────────────────────────────────────────────────────────

// rebuildMenu replaces the status-item menu to reflect the current lock state.
// Must be called on the main thread.
func (va *vaultApp) rebuildMenu() {
menu := appkit.NewMenuWithTitle("")

va.mu.Lock()
unlocked := va.session != nil && va.session.Active
dropPath := va.dropPath
va.mu.Unlock()

if !unlocked {
menu.AddItem(appkit.NewMenuItemWithAction("Create Vault…", "", func(objc.Object) { va.doCreate() }))
menu.AddItem(appkit.NewMenuItemWithAction("Unlock Vault…", "", func(objc.Object) { va.doUnlock() }))
menu.AddItem(appkit.MenuItem_SeparatorItem())
menu.AddItem(appkit.NewMenuItemWithAction("Quit", "q", func(objc.Object) { va.app.Terminate(nil) }))
} else {
status := appkit.NewMenuItemWithSelector(
"Watching: "+truncatePath(dropPath, 38), "", objc.Selector{})
status.SetEnabled(false)
menu.AddItem(status)

menu.AddItem(appkit.MenuItem_SeparatorItem())
menu.AddItem(appkit.NewMenuItemWithAction("Browse Entries…", "", func(objc.Object) { va.doBrowse() }))
menu.AddItem(appkit.MenuItem_SeparatorItem())
menu.AddItem(appkit.NewMenuItemWithAction("Lock Vault", "", func(objc.Object) { va.doLock() }))
menu.AddItem(appkit.MenuItem_SeparatorItem())
menu.AddItem(appkit.NewMenuItemWithAction("Quit", "q", func(objc.Object) {
va.shutdown()
va.app.Terminate(nil)
}))
}

va.statusItem.SetMenu(menu)
}

// ── Create ────────────────────────────────────────────────────────────────────

func (va *vaultApp) doCreate() {
vaultDir, ok := pickFolder("Select or create the vault folder", true)
if !ok {
return
}
dropDir, ok := pickFolder("Select the drop folder (files placed here are auto-encrypted)", true)
if !ok {
return
}
pass, ok := askNewPassword()
if !ok {
return
}
if err := vault.CreateVault(vaultDir, pass); err != nil {
showError("Create vault failed", err)
return
}
va.startSession(vaultDir, dropDir, pass)
}

// ── Unlock ────────────────────────────────────────────────────────────────────

func (va *vaultApp) doUnlock() {
vaultDir, ok := pickFolder("Select the vault folder", false)
if !ok {
return
}
dropDir, ok := pickFolder("Select the drop folder to watch", true)
if !ok {
return
}
pass, ok := askPassword("Vault Password", "Enter the password for this vault.")
if !ok {
return
}
va.startSession(vaultDir, dropDir, pass)
}

// startSession unlocks the vault and starts the file watcher.
func (va *vaultApp) startSession(vaultDir, dropDir, pass string) {
sess := new(vault.Session)
if err := vault.UnlockVault(sess, vaultDir, pass); err != nil {
showError("Unlock failed", err)
return
}
if err := os.MkdirAll(dropDir, 0700); err != nil {
showError("Drop folder error", err)
return
}

logFn := func(msg string) {
dispatch.MainQueue().DispatchAsync(func() { va.notify(msg) })
}

w, err := watcher.New(sess, dropDir, logFn)
if err != nil {
showError("Watcher init", err)
return
}
if err := w.Start(); err != nil {
showError("Watcher start", err)
return
}

va.mu.Lock()
va.session = sess
va.vaultPath = vaultDir
va.dropPath = dropDir
va.w = w
va.mu.Unlock()

dispatch.MainQueue().DispatchAsync(func() {
va.setIcon(false)
va.rebuildMenu()
})
}

// ── Lock ──────────────────────────────────────────────────────────────────────

func (va *vaultApp) doLock() {
va.shutdown()
dispatch.MainQueue().DispatchAsync(func() {
va.setIcon(true)
va.rebuildMenu()
})
}

// shutdown stops the watcher and wipes keys from memory.
func (va *vaultApp) shutdown() {
va.mu.Lock()
w := va.w
sess := va.session
va.w = nil
va.session = nil
va.mu.Unlock()

if w != nil {
w.Stop()
}
if sess != nil {
sess.LockAndWipe()
}
}

// ── Browse entries ────────────────────────────────────────────────────────────

type browserState struct {
tv       appkit.TableView
mu       sync.Mutex
entries  []vault.IndexEntry
selected int // -1 = none
}

func (va *vaultApp) doBrowse() {
va.mu.Lock()
sess := va.session
va.mu.Unlock()
if sess == nil {
return
}

idx, err := vault.LoadIndexForSession(sess)
if err != nil {
showError("Load index", err)
return
}

entries := sortedEntries(idx.Entries)
bs := &browserState{entries: entries, selected: -1}
va.openBrowserWindow(sess, bs)
}

func (va *vaultApp) openBrowserWindow(sess *vault.Session, bs *browserState) {
w := appkit.NewWindowWithSize(740, 500)
objc.Retain(&w)
w.SetTitle("nexvault — Entry Browser")
w.SetReleasedWhenClosed(false)
w.SetMinSize(foundation.Size{Width: 500, Height: 300})

// ── Table ──────────────────────────────────────────────────────────────

tv := appkit.NewTableView()
bs.tv = tv
tv.SetRowHeight(19)
tv.SetUsesAlternatingRowBackgroundColors(true)
tv.SetStyle(appkit.TableViewStyleFullWidth)
tv.SetColumnAutoresizingStyle(appkit.TableViewUniformColumnAutoresizingStyle)
tv.SetGridStyleMask(appkit.TableViewSolidHorizontalGridLineMask)

addCol := func(id, title string, width float64) {
col := appkit.NewTableColumnWithIdentifier(id)
col.SetTitle(title)
col.SetWidth(width)
col.SetMinWidth(60)
tv.AddTableColumn(col)
}
addCol("path", "Vault Path", 400)
addCol("size", "Size", 90)
addCol("date", "Added", 140)

// Data source (implements PTableViewDataSource via a local struct)
ds := &tableDS{bs: bs}
tv.SetDataSource(ds)

// Selection delegate
tvd := &appkit.TableViewDelegate{}
tvd.SetTableViewSelectionDidChange(func(foundation.Notification) {
bs.selected = tv.SelectedRow()
})
tv.SetDelegate(tvd)

// ── Scroll view ────────────────────────────────────────────────────────

sv := appkit.NewScrollView()
sv.SetFrameSize(foundation.Size{
Width:  w.ContentView().Frame().Size.Width,
Height: w.ContentView().Frame().Size.Height - 44,
})
sv.SetFrameOrigin(foundation.Point{X: 0, Y: 44})
sv.SetAutoresizingMask(appkit.ViewWidthSizable | appkit.ViewHeightSizable)
sv.SetDocumentView(tv)
sv.SetHasVerticalScroller(true)
sv.SetAutohidesScrollers(true)

// ── Toolbar ────────────────────────────────────────────────────────────

toolbar := appkit.NewViewWithFrame(foundation.Rect{
Size: foundation.Size{Width: w.ContentView().Frame().Size.Width, Height: 44},
})
toolbar.SetAutoresizingMask(appkit.ViewWidthSizable)

addBtn := func(title string, x float64, fn func()) appkit.Button {
btn := appkit.NewButtonWithTitle(title)
btn.SetBezelStyle(appkit.BezelStyleRounded)
btn.SetFrame(foundation.Rect{
Origin: foundation.Point{X: x, Y: 8},
Size:   foundation.Size{Width: 110, Height: 28},
})
action.Set(btn, func(objc.Object) { fn() })
toolbar.AddSubview(btn)
return btn
}
addBtn("Decrypt…", 12, func() { va.doDecryptSelected(sess, bs) })
addBtn("Delete…", 130, func() { va.doDeleteSelected(sess, bs) })
addBtn("Refresh", 248, func() { va.doRefreshBrowser(sess, bs) })

w.ContentView().AddSubview(toolbar)
w.ContentView().AddSubview(sv)

// ── Show ───────────────────────────────────────────────────────────────

w.Center()
w.MakeKeyAndOrderFront(nil)
va.app.SetActivationPolicy(appkit.ApplicationActivationPolicyRegular)
va.app.ActivateIgnoringOtherApps(true)

wd := &appkit.WindowDelegate{}
wd.SetWindowWillClose(func(foundation.Notification) {
// Return to menu-bar-only mode when the browser window is closed.
va.app.SetActivationPolicy(appkit.ApplicationActivationPolicyProhibited)
w.SetReleasedWhenClosed(true)
})
w.SetDelegate(wd)
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

func (va *vaultApp) doDecryptSelected(sess *vault.Session, bs *browserState) {
bs.mu.Lock()
sel := bs.selected
entries := bs.entries
bs.mu.Unlock()

if sel < 0 || sel >= len(entries) {
showInfo("No Selection", "Select an entry in the list first.")
return
}
entry := entries[sel]

sp := appkit.SavePanel_SavePanel()
sp.SetNameFieldStringValue(filepath.Base(entry.VaultRelPath))
sp.SetCanCreateDirectories(true)
if sp.RunModal() != appkit.ModalResponseOK {
return
}
outPath := sp.URL().Path()
if outPath == "" {
return
}

go func() {
f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
if err != nil {
dispatch.MainQueue().DispatchAsync(func() { showError("Decrypt", err) })
return
}
n, err := vault.DecryptToWriterByVaultPath(sess, entry.VaultRelPath, f)
_ = f.Close()
if err != nil {
_ = os.Remove(outPath)
dispatch.MainQueue().DispatchAsync(func() { showError("Decrypt", err) })
return
}
dispatch.MainQueue().DispatchAsync(func() {
showInfo("Decrypted", fmt.Sprintf(
"%s\n\n→ %s\n(%s)", entry.VaultRelPath, outPath, formatSize(n)))
})
}()
}

// ── Delete ────────────────────────────────────────────────────────────────────

func (va *vaultApp) doDeleteSelected(sess *vault.Session, bs *browserState) {
bs.mu.Lock()
sel := bs.selected
entries := bs.entries
bs.mu.Unlock()

if sel < 0 || sel >= len(entries) {
showInfo("No Selection", "Select an entry in the list first.")
return
}
entry := entries[sel]

if !askConfirm("Delete Entry",
fmt.Sprintf("Permanently delete:\n\n%s\n\nThe encrypted blob will be erased.", entry.VaultRelPath)) {
return
}

go func() {
if err := vault.DeleteEntry(sess, entry.VaultRelPath); err != nil {
dispatch.MainQueue().DispatchAsync(func() { showError("Delete", err) })
return
}
dispatch.MainQueue().DispatchAsync(func() { va.doRefreshBrowser(sess, bs) })
}()
}

// ── Refresh ───────────────────────────────────────────────────────────────────

func (va *vaultApp) doRefreshBrowser(sess *vault.Session, bs *browserState) {
idx, err := vault.LoadIndexForSession(sess)
if err != nil {
showError("Refresh", err)
return
}

bs.mu.Lock()
bs.entries = sortedEntries(idx.Entries)
bs.selected = -1
bs.mu.Unlock()

bs.tv.ReloadData()
}

// ── tableDS — minimal PTableViewDataSource implementation ────────────────────

// tableDS implements appkit.PTableViewDataSource using closures over
// *browserState. Only the two methods the table actually calls are wired up;
// all remaining optional methods return false from their Has... guards.
type tableDS struct{ bs *browserState }

func (t *tableDS) NumberOfRowsInTableView(_ appkit.TableView) int {
t.bs.mu.Lock()
defer t.bs.mu.Unlock()
return len(t.bs.entries)
}
func (t *tableDS) HasNumberOfRowsInTableView() bool { return true }

func (t *tableDS) TableViewObjectValueForTableColumnRow(_ appkit.TableView, col appkit.TableColumn, row int) objc.Object {
t.bs.mu.Lock()
defer t.bs.mu.Unlock()
if row < 0 || row >= len(t.bs.entries) {
return foundation.String_StringWithString("")
}
e := t.bs.entries[row]
switch col.Identifier() {
case "path":
return foundation.String_StringWithString(e.VaultRelPath)
case "size":
return foundation.String_StringWithString(formatSize(e.Size))
case "date":
return foundation.String_StringWithString(time.Unix(e.Added, 0).Format("2006-01-02 15:04"))
}
return foundation.String_StringWithString("")
}
func (t *tableDS) HasTableViewObjectValueForTableColumnRow() bool { return true }

// Unimplemented optional methods — the Has... guards prevent them being called.
func (t *tableDS) TableViewSetObjectValueForTableColumnRow(_ appkit.TableView, _ objc.Object, _ appkit.TableColumn, _ int) {
}
func (t *tableDS) HasTableViewSetObjectValueForTableColumnRow() bool { return false }
func (t *tableDS) TableViewSortDescriptorsDidChange(_ appkit.TableView, _ []foundation.SortDescriptor) {
}
func (t *tableDS) HasTableViewSortDescriptorsDidChange() bool { return false }
func (t *tableDS) TableViewDraggingSessionEndedAtPointOperation(_ appkit.TableView, _ appkit.DraggingSession, _ foundation.Point, _ appkit.DragOperation) {
}
func (t *tableDS) HasTableViewDraggingSessionEndedAtPointOperation() bool { return false }
func (t *tableDS) TableViewDraggingSessionWillBeginAtPointForRowIndexes(_ appkit.TableView, _ appkit.DraggingSession, _ foundation.Point, _ foundation.IndexSet) {
}
func (t *tableDS) HasTableViewDraggingSessionWillBeginAtPointForRowIndexes() bool { return false }
func (t *tableDS) TableViewAcceptDropRowDropOperation(_ appkit.TableView, _ appkit.DraggingInfoObject, _ int, _ appkit.TableViewDropOperation) bool {
return false
}
func (t *tableDS) HasTableViewAcceptDropRowDropOperation() bool { return false }
func (t *tableDS) TableViewPasteboardWriterForRow(_ appkit.TableView, _ int) appkit.PasteboardWritingObject {
return appkit.PasteboardWritingObject{}
}
func (t *tableDS) HasTableViewPasteboardWriterForRow() bool { return false }
func (t *tableDS) TableViewUpdateDraggingItemsForDrag(_ appkit.TableView, _ appkit.DraggingInfoObject) {
}
func (t *tableDS) HasTableViewUpdateDraggingItemsForDrag() bool { return false }
func (t *tableDS) TableViewValidateDropProposedRowProposedDropOperation(_ appkit.TableView, _ appkit.DraggingInfoObject, _ int, _ appkit.TableViewDropOperation) appkit.DragOperation {
return appkit.DragOperationNone
}
func (t *tableDS) HasTableViewValidateDropProposedRowProposedDropOperation() bool { return false }

// ── Native dialogs ────────────────────────────────────────────────────────────

// pickFolder shows an NSOpenPanel configured for directory selection.
func pickFolder(title string, canCreate bool) (string, bool) {
p := appkit.OpenPanel_OpenPanel()
p.SetTitle(title)
p.SetCanChooseFiles(false)
p.SetCanChooseDirectories(true)
p.SetAllowsMultipleSelection(false)
p.SetCanCreateDirectories(canCreate)
if p.RunModal() != appkit.ModalResponseOK {
return "", false
}
urls := p.URLs()
if len(urls) == 0 {
return "", false
}
return urls[0].Path(), true
}

// askPassword shows an NSAlert with a single NSSecureTextField accessory.
func askPassword(title, info string) (string, bool) {
alert := appkit.NewAlert()
alert.SetMessageText(title)
alert.SetInformativeText(info)
alert.AddButtonWithTitle("OK")
alert.AddButtonWithTitle("Cancel")

field := appkit.NewSecureTextFieldWithFrame(foundation.Rect{
Size: foundation.Size{Width: 260, Height: 22},
})
field.SetPlaceholderString("Password")
alert.SetAccessoryView(field)
alert.Window().MakeFirstResponder(field)

if alert.RunModal() != appkit.AlertFirstButtonReturn {
return "", false
}
return field.StringValue(), true
}

// askNewPassword shows an NSAlert with two stacked NSSecureTextFields and
// re-prompts on mismatch or empty input.
func askNewPassword() (string, bool) {
for {
alert := appkit.NewAlert()
alert.SetMessageText("Set Vault Password")
alert.SetInformativeText("Choose a strong password. There is no recovery mechanism.")
alert.AddButtonWithTitle("Set Password")
alert.AddButtonWithTitle("Cancel")

container := appkit.NewViewWithFrame(foundation.Rect{
Size: foundation.Size{Width: 260, Height: 56},
})
f1 := appkit.NewSecureTextFieldWithFrame(foundation.Rect{
Origin: foundation.Point{X: 0, Y: 30},
Size:   foundation.Size{Width: 260, Height: 22},
})
f1.SetPlaceholderString("New password")
f2 := appkit.NewSecureTextFieldWithFrame(foundation.Rect{
Origin: foundation.Point{X: 0, Y: 2},
Size:   foundation.Size{Width: 260, Height: 22},
})
f2.SetPlaceholderString("Confirm password")
container.AddSubview(f1)
container.AddSubview(f2)
alert.SetAccessoryView(container)
alert.Window().MakeFirstResponder(f1)

if alert.RunModal() != appkit.AlertFirstButtonReturn {
return "", false
}
p1, p2 := f1.StringValue(), f2.StringValue()
if p1 == "" {
showInfo("Empty Password", "Password must not be empty.")
continue
}
if p1 != p2 {
showInfo("Mismatch", "Passwords do not match. Please try again.")
continue
}
return p1, true
}
}

// askConfirm shows a warning-style NSAlert; returns true iff user clicked Confirm.
func askConfirm(title, msg string) bool {
alert := appkit.NewAlert()
alert.SetAlertStyle(appkit.AlertStyleWarning)
alert.SetMessageText(title)
alert.SetInformativeText(msg)
alert.AddButtonWithTitle("Confirm")
alert.AddButtonWithTitle("Cancel")
return alert.RunModal() == appkit.AlertFirstButtonReturn
}

// showError presents a native critical-style error alert.
func showError(context string, err error) {
alert := appkit.NewAlert()
alert.SetAlertStyle(appkit.AlertStyleCritical)
alert.SetMessageText(context)
alert.SetInformativeText(err.Error())
alert.AddButtonWithTitle("OK")
alert.RunModal()
}

// showInfo presents a native informational alert.
func showInfo(title, msg string) {
alert := appkit.NewAlert()
alert.SetMessageText(title)
alert.SetInformativeText(msg)
alert.AddButtonWithTitle("OK")
alert.RunModal()
}

// notify delivers a brief NSUserNotification for watcher events.
func (va *vaultApp) notify(msg string) {
notif := objc.Call[objc.Object](objc.GetClass("NSUserNotification"), objc.Sel("new"))
objc.Call[objc.Void](notif, objc.Sel("setTitle:"), "nexvault")
objc.Call[objc.Void](notif, objc.Sel("setInformativeText:"), msg)
center := objc.Call[objc.Object](objc.GetClass("NSUserNotificationCenter"), objc.Sel("defaultUserNotificationCenter"))
objc.Call[objc.Void](center, objc.Sel("deliverNotification:"), notif)
}

// ── Utility ───────────────────────────────────────────────────────────────────

func sortedEntries(in []vault.IndexEntry) []vault.IndexEntry {
out := make([]vault.IndexEntry, len(in))
copy(out, in)
sort.Slice(out, func(i, j int) bool {
return strings.ToLower(out[i].VaultRelPath) < strings.ToLower(out[j].VaultRelPath)
})
return out
}

func formatSize(n int64) string {
switch {
case n >= 1<<30:
return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
case n >= 1<<20:
return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
case n >= 1<<10:
return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
default:
return fmt.Sprintf("%d B", n)
}
}

// truncatePath shortens a path to at most max runes, trimming from the left.
func truncatePath(p string, max int) string {
runes := []rune(p)
if len(runes) <= max {
return p
}
return "…" + string(runes[len(runes)-(max-1):])
}
