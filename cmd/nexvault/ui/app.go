// Package ui is the cross-platform entry point for nexvault.
//
// When launched without arguments (double-clicking the binary or app bundle)
// a Fyne GUI opens with a proper Dock icon on macOS and a taskbar entry on
// Windows / Linux. When run with a known sub-command (create, watch, list,
// decrypt, delete) the traditional text-based CLI is used instead, which
// makes scripting and automation straightforward on all platforms.
package ui

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/term"

	"nexvault/internal/vault"
	"nexvault/internal/watcher"
)

// ── Entry point ───────────────────────────────────────────────────────────────

// Run is the application entry point.
// If a known CLI sub-command is present it runs in CLI mode; otherwise the
// Fyne GUI is launched.
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

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GUI                                                                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// vaultApp holds all state for the Fyne GUI.
type vaultApp struct {
	app fyne.App
	win fyne.Window

	mu        sync.Mutex
	session   *vault.Session
	vaultPath string
	dropPath  string
	w         *watcher.Watcher
	entries   []vault.IndexEntry
	selected  int            // row index for decrypt; -1 = nothing selected
	selectedRows map[int]bool // rows checked for bulk delete

	// statusPending guards against flooding the Fyne event queue with
	// redundant status-label updates (e.g. during bulk encryption of many
	// files). At most one updateStatus closure is queued at a time.
	statusPending atomic.Bool

	// refreshPending coalesces entry-table refresh requests so that at most
	// one refreshEntries goroutine is running at a time even when many files
	// are encrypted in rapid succession.
	refreshPending atomic.Bool

	// locking prevents re-entrant doLock calls (e.g. toolbar button clicked
	// while a tray-menu lock is already in progress).
	locking atomic.Bool

	// UI elements that are updated reactively
	statusLabel  *widget.Label
	table        *widget.Table
	decryptBtn   *widget.Button
	deleteBtn    *widget.Button
	lockBtn      *widget.Button
	openBtn      *widget.Button
	createBtn    *widget.Button
	selectAllBtn *widget.Button
}

func runGUI() {
	a := app.NewWithID("io.nexvault.app")
	va := &vaultApp{app: a, selected: -1, selectedRows: make(map[int]bool)}
	va.buildWindow()
	va.setupTray()
	a.Run()
}

// ── Window construction ───────────────────────────────────────────────────────

func (va *vaultApp) buildWindow() {
	va.win = va.app.NewWindow("nexvault")
	va.win.Resize(fyne.NewSize(960, 560))
	va.win.SetMaster()

	va.statusLabel = widget.NewLabel("Status: locked — open or create a vault to begin")
	va.statusLabel.Wrapping = fyne.TextWrapWord

	va.table = va.buildTable()

	toolbar := va.buildToolbar()

	content := container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), va.statusLabel),
		nil, nil,
		container.NewStack(va.table),
	)

	va.win.SetContent(container.NewPadded(content))

	// Closing the window just hides it (tray stays active); Quit from the
	// tray or menu fully exits.
	va.win.SetCloseIntercept(func() {
		va.win.Hide()
	})

	va.win.Show()
}

func (va *vaultApp) buildToolbar() *widget.Toolbar {
	va.createBtn = widget.NewButton("New Vault", func() { va.showCreateDialog() })
	va.openBtn = widget.NewButton("Open Vault", func() { va.showOpenDialog() })
	va.lockBtn = widget.NewButton("Lock", func() { go va.doLock() })
	va.lockBtn.Importance = widget.DangerImportance
	va.lockBtn.Disable()

	va.decryptBtn = widget.NewButton("Decrypt…", func() { va.doDecrypt() })
	va.decryptBtn.Disable()
	va.selectAllBtn = widget.NewButton("Select All", func() { va.doSelectAll() })
	va.selectAllBtn.Disable()
	va.deleteBtn = widget.NewButton("Delete", func() { va.doDelete() })
	va.deleteBtn.Disable()
	refreshBtn := widget.NewButton("Refresh", func() { va.doRefresh() })

	return widget.NewToolbar(
		&toolbarWidget{va.createBtn},
		&toolbarWidget{va.openBtn},
		widget.NewToolbarSeparator(),
		&toolbarWidget{va.lockBtn},
		widget.NewToolbarSpacer(),
		&toolbarWidget{va.decryptBtn},
		&toolbarWidget{va.selectAllBtn},
		&toolbarWidget{va.deleteBtn},
		widget.NewToolbarSeparator(),
		&toolbarWidget{refreshBtn},
	)
}

// toolbarWidget wraps a *widget.Button to satisfy the fyne.ToolbarItem interface.
type toolbarWidget struct{ btn *widget.Button }

func (t *toolbarWidget) ToolbarObject() fyne.CanvasObject { return t.btn }

func (va *vaultApp) buildTable() *widget.Table {
	headers := []string{"", "Vault Path", "Size", "Added"}

	tbl := widget.NewTableWithHeaders(
		func() (int, int) {
			va.mu.Lock()
			defer va.mu.Unlock()
			return len(va.entries), 4
		},
		// CreateCell returns a container holding both a checkbox (col 0) and a
		// label (cols 1-3). UpdateCell shows or hides the appropriate widget.
		func() fyne.CanvasObject {
			return container.NewStack(
				widget.NewCheck("", func(bool) {}),
				widget.NewLabel(""),
			)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			c := obj.(*fyne.Container)
			chk := c.Objects[0].(*widget.Check)
			lbl := c.Objects[1].(*widget.Label)

			va.mu.Lock()
			if id.Row < 0 || id.Row >= len(va.entries) {
				va.mu.Unlock()
				chk.Hide()
				lbl.SetText("")
				lbl.Show()
				return
			}
			e := va.entries[id.Row]
			checked := va.selectedRows[id.Row]
			va.mu.Unlock()

			if id.Col == 0 {
				lbl.Hide()
				chk.Show()
				row := id.Row
				// Nil the callback before updating the checked state so that
				// programmatic updates during cell recycling don't fire it.
				chk.OnChanged = nil
				chk.Checked = checked
				chk.Refresh()
				chk.OnChanged = func(v bool) {
					va.mu.Lock()
					if v {
						va.selectedRows[row] = true
					} else {
						delete(va.selectedRows, row)
					}
					count := len(va.selectedRows)
					total := len(va.entries)
					sel := va.selected
					va.mu.Unlock()
					// OnChanged runs on the Fyne event loop; update UI directly.
					if count > 0 || sel >= 0 {
						va.deleteBtn.Enable()
					} else {
						va.deleteBtn.Disable()
					}
					if count > 0 && count == total {
						va.selectAllBtn.SetText("Deselect All")
					} else {
						va.selectAllBtn.SetText("Select All")
					}
				}
				return
			}

			chk.Hide()
			lbl.Show()
			switch id.Col {
			case 1:
				lbl.SetText(e.VaultRelPath)
			case 2:
				lbl.SetText(guiFormatSize(e.Size))
			case 3:
				lbl.SetText(time.Unix(e.Added, 0).Format("2006-01-02 15:04"))
			}
		},
	)

	tbl.ShowHeaderRow = true
	tbl.ShowHeaderColumn = false
	tbl.UpdateHeader = func(id widget.TableCellID, obj fyne.CanvasObject) {
		l := obj.(*widget.Label)
		if id.Col >= 0 && id.Col < len(headers) {
			l.SetText(headers[id.Col])
			l.TextStyle = fyne.TextStyle{Bold: true}
		}
	}

	tbl.SetColumnWidth(0, 36)
	tbl.SetColumnWidth(1, 480)
	tbl.SetColumnWidth(2, 90)
	tbl.SetColumnWidth(3, 150)

	tbl.OnSelected = func(id widget.TableCellID) {
		va.mu.Lock()
		va.selected = id.Row
		va.mu.Unlock()
		va.decryptBtn.Enable()
		va.deleteBtn.Enable()
	}
	tbl.OnUnselected = func(_ widget.TableCellID) {
		va.mu.Lock()
		va.selected = -1
		count := len(va.selectedRows)
		va.mu.Unlock()
		va.decryptBtn.Disable()
		if count == 0 {
			va.deleteBtn.Disable()
		}
	}

	return tbl
}

// ── System tray ───────────────────────────────────────────────────────────────

func (va *vaultApp) setupTray() {
	desk, ok := va.app.(desktop.App)
	if !ok {
		return
	}
	desk.SetSystemTrayIcon(theme.StorageIcon())
	desk.SetSystemTrayMenu(fyne.NewMenu("nexvault",
		fyne.NewMenuItem("Show nexvault", func() {
			va.win.Show()
			va.win.RequestFocus()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Lock Vault", func() { go va.doLock() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { va.app.Quit() }),
	))
}

// ── Vault operations ──────────────────────────────────────────────────────────

// showCreateDialog presents a form for choosing vault dir, drop dir, and password.
func (va *vaultApp) showCreateDialog() {
	vaultDir := ""
	dropDir := ""

	vaultLabel := widget.NewLabel("(not selected)")
	dropLabel := widget.NewLabel("(not selected)")

	vaultPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderNewIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			vaultDir = u.Path()
			vaultLabel.SetText(vaultDir)
		}, va.win)
	})
	dropPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			dropDir = u.Path()
			dropLabel.SetText(dropDir)
		}, va.win)
	})

	pass1 := widget.NewPasswordEntry()
	pass1.SetPlaceHolder("New password")
	pass2 := widget.NewPasswordEntry()
	pass2.SetPlaceHolder("Confirm password")

	form := container.NewVBox(
		widget.NewLabelWithStyle("Vault Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, vaultPickBtn, vaultLabel),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Drop Folder (auto-encrypt incoming files)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, dropPickBtn, dropLabel),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		pass1,
		pass2,
	)

	d := dialog.NewCustomConfirm("Create New Vault", "Create", "Cancel", form,
		func(ok bool) {
			if !ok {
				return
			}
			if vaultDir == "" || dropDir == "" {
				dialog.ShowError(fmt.Errorf("vault and drop folders are required"), va.win)
				return
			}
			p := pass1.Text
			if p == "" {
				dialog.ShowError(fmt.Errorf("password must not be empty"), va.win)
				return
			}
			if p != pass2.Text {
				dialog.ShowError(fmt.Errorf("passwords do not match"), va.win)
				return
			}
			go va.doCreate(vaultDir, dropDir, p)
		}, va.win)
	d.Resize(fyne.NewSize(540, 0))
	d.Show()
}

func (va *vaultApp) doCreate(vaultDir, dropDir, pass string) {
	if err := vault.CreateVault(vaultDir, pass); err != nil {
		va.showErrorOnMain("Create vault", err)
		return
	}
	va.startSession(vaultDir, dropDir, pass)
}

// showOpenDialog presents a form for choosing an existing vault dir, drop dir,
// and the unlock password.
func (va *vaultApp) showOpenDialog() {
	vaultDir := ""
	dropDir := ""

	vaultLabel := widget.NewLabel("(not selected)")
	dropLabel := widget.NewLabel("(not selected)")

	vaultPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			vaultDir = u.Path()
			vaultLabel.SetText(vaultDir)
		}, va.win)
	})
	dropPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			dropDir = u.Path()
			dropLabel.SetText(dropDir)
		}, va.win)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Vault password")

	form := container.NewVBox(
		widget.NewLabelWithStyle("Vault Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, vaultPickBtn, vaultLabel),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Drop Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, dropPickBtn, dropLabel),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		passEntry,
	)

	d := dialog.NewCustomConfirm("Open Vault", "Open", "Cancel", form,
		func(ok bool) {
			if !ok {
				return
			}
			if vaultDir == "" {
				dialog.ShowError(fmt.Errorf("vault folder is required"), va.win)
				return
			}
			if dropDir == "" {
				dialog.ShowError(fmt.Errorf("drop folder is required"), va.win)
				return
			}
			go va.startSession(vaultDir, dropDir, passEntry.Text)
		}, va.win)
	d.Resize(fyne.NewSize(540, 0))
	d.Show()
}

// startSession unlocks the vault and starts the file watcher.
func (va *vaultApp) startSession(vaultDir, dropDir, pass string) {
	sess := new(vault.Session)
	if err := vault.UnlockVault(sess, vaultDir, pass); err != nil {
		va.showErrorOnMain("Unlock failed", err)
		return
	}
	if err := os.MkdirAll(dropDir, 0700); err != nil {
		va.showErrorOnMain("Drop folder", err)
		return
	}

	logFn := func(msg string) {
		// Coalesced status update: at most one fyne.Do closure is ever
		// queued regardless of how many files are encrypted in quick
		// succession (e.g. bulk-importing 40 000 items).
		va.updateStatus()
		// Refresh the entry table so newly-encrypted files appear without
		// the user having to click the Refresh button manually. The
		// refreshPending flag coalesces rapid bursts: if a refresh is already
		// in progress we skip the extra goroutine — the running one will read
		// the latest index when it completes.
		if va.refreshPending.CompareAndSwap(false, true) {
			go func() {
				defer va.refreshPending.Store(false)
				va.refreshEntries()
			}()
		}
	}

	w, err := watcher.New(sess, dropDir, logFn)
	if err != nil {
		va.showErrorOnMain("Watcher init", err)
		return
	}
	if err := w.Start(); err != nil {
		va.showErrorOnMain("Watcher start", err)
		return
	}

	va.mu.Lock()
	va.session = sess
	va.vaultPath = vaultDir
	va.dropPath = dropDir
	va.w = w
	va.mu.Unlock()

	va.refreshEntries()
	va.setLocked(false)
	va.updateStatus()
}

func (va *vaultApp) doLock() {
	// Prevent re-entrant calls (e.g. button clicked twice, or toolbar button
	// and tray menu triggered concurrently).
	if !va.locking.CompareAndSwap(false, true) {
		return
	}
	defer va.locking.Store(false)

	va.mu.Lock()
	w := va.w
	sess := va.session
	va.w = nil
	va.session = nil
	va.vaultPath = ""
	va.dropPath = ""
	va.entries = nil
	va.selected = -1
	va.selectedRows = make(map[int]bool)
	va.mu.Unlock()

	// Disable interactive controls immediately so the user cannot trigger
	// another lock (or decrypt/delete) while the watcher is still draining.
	// This must happen before w.Stop() because Stop() blocks until all
	// pending files have been encrypted.
	fyne.Do(func() {
		va.lockBtn.Disable()
		va.decryptBtn.Disable()
		va.deleteBtn.Disable()
		va.selectAllBtn.Disable()
	})

	if w != nil {
		w.Stop()
	}
	if sess != nil {
		sess.LockAndWipe()
	}
	va.setLocked(true)
	fyne.Do(func() { va.table.Refresh() })
	va.updateStatus()
}

// setLocked adjusts which toolbar buttons are enabled.
// Safe to call from any goroutine.
func (va *vaultApp) setLocked(locked bool) {
	fyne.Do(func() {
		if locked {
			va.lockBtn.Disable()
			va.decryptBtn.Disable()
			va.deleteBtn.Disable()
			va.selectAllBtn.Disable()
			va.selectAllBtn.SetText("Select All")
		} else {
			va.lockBtn.Enable()
			va.selectAllBtn.Enable()
		}
	})
}

func (va *vaultApp) updateStatus() {
	// Only queue one fyne.Do closure at a time. If an update is already
	// pending we skip the queue — the in-flight closure will read the
	// latest state when it actually runs on the Fyne goroutine.
	if !va.statusPending.CompareAndSwap(false, true) {
		return
	}
	fyne.Do(func() {
		va.mu.Lock()
		sess := va.session
		vp := va.vaultPath
		dp := va.dropPath
		va.mu.Unlock()

		var text string
		if sess == nil || !sess.Active {
			text = "Status: locked — open or create a vault to begin"
		} else {
			text = fmt.Sprintf("Status: unlocked  •  Vault: %s  •  Watching: %s", vp, dp)
		}
		va.statusLabel.SetText(text)
		// Clear the flag only after the widget update is complete so that
		// no new closure can be queued during the window between reading
		// state and applying it to the label.
		va.statusPending.Store(false)
	})
}

// ── Entry table ───────────────────────────────────────────────────────────────

func (va *vaultApp) refreshEntries() {
	va.mu.Lock()
	sess := va.session
	va.mu.Unlock()
	if sess == nil {
		return
	}

	idx, err := vault.LoadIndexForSession(sess)
	if err != nil {
		va.showErrorOnMain("Load index", err)
		return
	}

	sorted := make([]vault.IndexEntry, len(idx.Entries))
	copy(sorted, idx.Entries)
	sort.Slice(sorted, func(i, j int) bool {
		return strings.ToLower(sorted[i].VaultRelPath) < strings.ToLower(sorted[j].VaultRelPath)
	})

	va.mu.Lock()
	va.entries = sorted
	va.selected = -1
	va.selectedRows = make(map[int]bool)
	va.mu.Unlock()

	fyne.Do(func() {
		va.table.Refresh()
		va.decryptBtn.Disable()
		va.deleteBtn.Disable()
		va.selectAllBtn.SetText("Select All")
	})
}

func (va *vaultApp) doRefresh() {
	go va.refreshEntries()
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

func (va *vaultApp) doDecrypt() {
	va.mu.Lock()
	sel := va.selected
	entries := va.entries
	sess := va.session
	va.mu.Unlock()

	if sel < 0 || sel >= len(entries) || sess == nil {
		return
	}
	entry := entries[sel]

	sd := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil || wc == nil {
			return
		}
		go func() {
			defer wc.Close()
			n, err := vault.DecryptToWriterByVaultPath(sess, entry.VaultRelPath, wc)
			if err != nil {
				va.showErrorOnMain("Decrypt failed", err)
				return
			}
			va.showInfoOnMain("Decrypted",
				fmt.Sprintf("%s\n\nSaved to: %s\n(%s)",
					entry.VaultRelPath, wc.URI().Path(), guiFormatSize(n)))
		}()
	}, va.win)
	sd.SetFileName(filepath.Base(entry.VaultRelPath))
	sd.Show()
}

// ── Delete ────────────────────────────────────────────────────────────────────

func (va *vaultApp) doDelete() {
	va.mu.Lock()
	sel := va.selected
	entries := va.entries
	sess := va.session
	// Collect checked rows in sorted order.
	checkedRows := make([]int, 0, len(va.selectedRows))
	for r := range va.selectedRows {
		checkedRows = append(checkedRows, r)
	}
	va.mu.Unlock()

	if sess == nil {
		return
	}

	// If no checkboxes are ticked, fall back to deleting the single selected row.
	if len(checkedRows) == 0 {
		if sel < 0 || sel >= len(entries) {
			return
		}
		entry := entries[sel]
		dialog.ShowConfirm("Delete Entry",
			fmt.Sprintf("Permanently delete:\n\n%s\n\nThis cannot be undone.", entry.VaultRelPath),
			func(ok bool) {
				if !ok {
					return
				}
				go func() {
					if err := vault.DeleteEntry(sess, entry.VaultRelPath); err != nil {
						va.showErrorOnMain("Delete failed", err)
						return
					}
					va.refreshEntries()
				}()
			}, va.win)
		return
	}

	// Multi-delete: gather paths for all checked rows.
	sort.Ints(checkedRows)
	paths := make([]string, 0, len(checkedRows))
	for _, r := range checkedRows {
		if r >= 0 && r < len(entries) {
			paths = append(paths, entries[r].VaultRelPath)
		}
	}
	if len(paths) == 0 {
		return
	}

	var msg string
	if len(paths) == 1 {
		msg = fmt.Sprintf("Permanently delete:\n\n%s\n\nThis cannot be undone.", paths[0])
	} else {
		msg = fmt.Sprintf("Permanently delete %d entries?\n\nThis cannot be undone.", len(paths))
	}
	dialog.ShowConfirm("Delete Entries", msg, func(ok bool) {
		if !ok {
			return
		}
		go func() {
			if err := vault.DeleteEntries(sess, paths); err != nil {
				va.showErrorOnMain("Delete failed", err)
				return
			}
			va.refreshEntries()
		}()
	}, va.win)
}

// doSelectAll selects all entries when some or none are selected, or clears the
// selection when every entry is already checked.
func (va *vaultApp) doSelectAll() {
	va.mu.Lock()
	total := len(va.entries)
	allSelected := len(va.selectedRows) == total && total > 0
	if allSelected {
		va.selectedRows = make(map[int]bool)
	} else {
		for i := 0; i < total; i++ {
			va.selectedRows[i] = true
		}
	}
	count := len(va.selectedRows)
	va.mu.Unlock()

	fyne.Do(func() {
		va.table.Refresh()
		if count > 0 {
			va.deleteBtn.Enable()
			va.selectAllBtn.SetText("Deselect All")
		} else {
			va.selectAllBtn.SetText("Select All")
			va.mu.Lock()
			sel := va.selected
			va.mu.Unlock()
			if sel < 0 {
				va.deleteBtn.Disable()
			}
		}
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (va *vaultApp) showErrorOnMain(ctx string, err error) {
	// dialog.ShowError queues itself on the main thread internally.
	dialog.ShowError(fmt.Errorf("%s: %w", ctx, err), va.win)
}

func (va *vaultApp) showInfoOnMain(title, msg string) {
	dialog.ShowInformation(title, msg, va.win)
}

func guiFormatSize(n int64) string {
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

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  CLI                                                                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// runCLI handles the text-based interface used when a sub-command is given.
func runCLI() {
	if len(os.Args) < 2 {
		cliUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "create":
		cmdCreate(os.Args[2:])
	case "watch":
		cmdWatch(os.Args[2:])
	case "list", "ls":
		cmdList(os.Args[2:])
	case "decrypt", "get":
		cmdDecrypt(os.Args[2:])
	case "delete", "rm":
		cmdDelete(os.Args[2:])
	case "-h", "--help", "help":
		cliUsage()
	default:
		fmt.Fprintf(os.Stderr, "nexvault: unknown command %q\n\n", os.Args[1])
		cliUsage()
		os.Exit(1)
	}
}

func cliUsage() {
	fmt.Fprint(os.Stderr, `nexvault — encrypted file vault

usage:
  nexvault                       launch the graphical interface
  nexvault <command> [flags]     use the command-line interface

commands:
  create    initialise a new vault
  watch     watch a drop folder and auto-encrypt every file placed there
  list      list vault entries                           (aliases: ls)
  decrypt   decrypt a vault entry to disk               (aliases: get)
  delete    remove an entry from the vault              (aliases: rm)

flags:
  -vault <path>   vault directory (required by all commands)

watch flags:
  -drop  <path>   folder to watch for incoming files (required; created if absent)

decrypt flags:
  -entry <path>   vault-relative path of the entry (required)
  -out   <path>   destination file path (required)

delete flags:
  -entry <path>   vault-relative path of the entry (required)
`)
}

// ── create ───────────────────────────────────────────────────────────────────

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	cliMustParse(fs, args)
	cliRequireFlag("create", "-vault", *vaultDir)

	pass, err := cliReadNewPassword()
	cliDie(err)
	cliDie(vault.CreateVault(*vaultDir, pass))
	fmt.Printf("vault created: %s\n", *vaultDir)
}

// ── watch ────────────────────────────────────────────────────────────────────

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	dropDir := fs.String("drop", "", "folder to watch for incoming files (required)")
	cliMustParse(fs, args)
	cliRequireFlag("watch", "-vault", *vaultDir)
	cliRequireFlag("watch", "-drop", *dropDir)

	pass, err := cliReadPassword("vault password: ")
	cliDie(err)

	var sess vault.Session
	cliDie(cliWithMsg(vault.UnlockVault(&sess, *vaultDir, pass), "unlock failed"))
	fmt.Println("vault unlocked.")

	cliDie(os.MkdirAll(*dropDir, 0700))

	logFn := func(msg string) {
		fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
	}

	w, err := watcher.New(&sess, *dropDir, logFn)
	cliDie(err)
	cliDie(cliWithMsg(w.Start(), "watcher failed to start"))

	fmt.Printf("watching: %s\npress ctrl-c to lock and exit.\n", *dropDir)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	fmt.Println("\nlocking vault...")
	w.Stop()
	sess.LockAndWipe()
	fmt.Println("done.")
}

// ── list ─────────────────────────────────────────────────────────────────────

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	cliMustParse(fs, args)
	cliRequireFlag("list", "-vault", *vaultDir)

	sess := cliOpenSession(*vaultDir)
	defer sess.LockAndWipe()

	idx, err := vault.LoadIndexForSession(sess)
	cliDie(err)

	entries := append([]vault.IndexEntry(nil), idx.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].VaultRelPath) < strings.ToLower(entries[j].VaultRelPath)
	})

	if len(entries) == 0 {
		fmt.Println("vault is empty.")
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tSIZE\tGEN\tADDED")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n",
			e.VaultRelPath, e.Size, e.Gen,
			time.Unix(e.Added, 0).Format("2006-01-02 15:04"))
	}
	_ = tw.Flush()
}

// ── decrypt ──────────────────────────────────────────────────────────────────

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	entry := fs.String("entry", "", "vault-relative entry path (required)")
	outPath := fs.String("out", "", "output file path (required)")
	cliMustParse(fs, args)
	cliRequireFlag("decrypt", "-vault", *vaultDir)
	cliRequireFlag("decrypt", "-entry", *entry)
	cliRequireFlag("decrypt", "-out", *outPath)

	sess := cliOpenSession(*vaultDir)
	defer sess.LockAndWipe()

	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	cliDie(err)
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(*outPath)
		}
	}()

	n, err := vault.DecryptToWriterByVaultPath(sess, *entry, out)
	cliDie(err)
	ok = true
	fmt.Printf("decrypted: %s -> %s (%d bytes)\n", *entry, *outPath, n)
}

// ── delete ───────────────────────────────────────────────────────────────────

func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	entry := fs.String("entry", "", "vault-relative entry path (required)")
	cliMustParse(fs, args)
	cliRequireFlag("delete", "-vault", *vaultDir)
	cliRequireFlag("delete", "-entry", *entry)

	sess := cliOpenSession(*vaultDir)
	defer sess.LockAndWipe()

	fmt.Printf("delete %q from vault? [y/N] ", *entry)
	if !cliConfirmYN() {
		fmt.Println("aborted.")
		return
	}

	cliDie(vault.DeleteEntry(sess, *entry))
	fmt.Printf("deleted: %s\n", *entry)
}

// ── CLI helpers ───────────────────────────────────────────────────────────────

var stdinReader = bufio.NewReader(os.Stdin)

func cliOpenSession(vaultDir string) *vault.Session {
	pass, err := cliReadPassword("vault password: ")
	cliDie(err)
	sess := new(vault.Session)
	cliDie(cliWithMsg(vault.UnlockVault(sess, vaultDir, pass), "unlock failed"))
	return sess
}

func cliReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := stdinReader.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func cliReadNewPassword() (string, error) {
	p1, err := cliReadPassword("new vault password: ")
	if err != nil {
		return "", err
	}
	p2, err := cliReadPassword("confirm password:    ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passwords do not match")
	}
	if p1 == "" {
		return "", errors.New("password must not be empty")
	}
	return p1, nil
}

func cliConfirmYN() bool {
	line, _ := stdinReader.ReadString('\n')
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes"
}

func cliDie(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexvault: %v\n", err)
		os.Exit(1)
	}
}

func cliWithMsg(err error, msg string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

func cliMustParse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		cliDie(err)
	}
}

func cliRequireFlag(cmd, flagName, val string) {
	if val == "" {
		fmt.Fprintf(os.Stderr, "nexvault %s: %s is required\n", cmd, flagName)
		os.Exit(1)
	}
}
