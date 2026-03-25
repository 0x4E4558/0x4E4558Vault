// Package ui is the cross-platform entry point for nexvault.
//
// When launched without arguments (double-clicking the binary or app bundle)
// a Fyne GUI opens. On desktop platforms (macOS, Windows, Linux) a CLI is
// also available when a sub-command is passed on os.Args; see cli.go.
// On Android and iOS only the GUI is compiled in.
package ui

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"nexvault/internal/vault"
	"nexvault/internal/watcher"
)

// autoLockDuration is the period of inactivity after which an unlocked vault
// is automatically locked. 1800 seconds = 30 minutes.
const autoLockDuration = 1800 * time.Second

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
	// while a tray-menu lock is already in progress). It also means that the
	// window close-intercept and tray-Quit paths are safe if triggered rapidly
	// in succession — only the first call does real work.
	locking atomic.Bool

	// autoLockTimer fires doLock after autoLockDuration of the vault being
	// unlocked. It is started in startSession and cancelled in doLock.
	autoLockTimer *time.Timer

	// sessionGen is incremented each time a new session is started or doLock
	// runs. The auto-lock timer callback compares its captured generation
	// against the current value to skip locking if a new session has started
	// between when the timer fired and when the callback executes.
	sessionGen uint64

	// UI elements that are updated reactively
	statusLabel  *widget.Label
	table        *widget.Table
	decryptBtn   *widget.Button
	editBtn      *widget.Button
	deleteBtn    *widget.Button
	lockBtn      *widget.Button
	openBtn      *widget.Button
	createBtn    *widget.Button
	newNoteBtn   *widget.Button
	selectAllBtn *widget.Button
	importBtn    *widget.Button
}

func runGUI() {
	a := app.NewWithID("io.nexvault.app")
	a.SetIcon(iconVaultPNG)
	va := &vaultApp{app: a, selected: -1, selectedRows: make(map[int]bool)}
	va.buildWindow()
	va.setupTray()
	// Safety net: if the OS terminates the process while a vault is open,
	// wipe the in-memory keys before the process exits. This runs after
	// a.Run() returns (i.e. after Quit() is called).
	a.Lifecycle().SetOnStopped(func() {
		va.mu.Lock()
		sess := va.session
		w := va.w
		t := va.autoLockTimer
		va.session = nil
		va.w = nil
		va.autoLockTimer = nil
		va.mu.Unlock()
		if t != nil {
			t.Stop()
		}
		if w != nil {
			w.Stop()
		}
		if sess != nil {
			sess.LockAndWipe()
		}
	})
	a.Run()
}

// ── Window construction ───────────────────────────────────────────────────────

func (va *vaultApp) buildWindow() {
	va.win = va.app.NewWindow("nexvault")
	va.win.SetIcon(iconVaultPNG)
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

	// Add a menu bar so users have a standard place to find New Note and Quit.
	va.win.SetMainMenu(fyne.NewMainMenu(
		fyne.NewMenu("nexvault",
			fyne.NewMenuItem("New Encrypted Note", func() { va.doNewNote() }),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit nexvault", func() { go va.doLockAndQuit() }),
		),
	))

	// Closing the window locks the vault and exits the application so that
	// the terminal session (if any) is released immediately. Users who want
	// the vault to remain active should minimise the window instead of closing it.
	va.win.SetCloseIntercept(func() {
		go va.doLockAndQuit()
	})

	va.win.Show()
}

func (va *vaultApp) buildToolbar() *widget.Toolbar {
	va.createBtn = widget.NewButton("New Vault", func() { va.showCreateDialog() })
	va.openBtn = widget.NewButton("Open Vault", func() { va.showOpenDialog() })
	va.lockBtn = widget.NewButton("Lock", func() { go va.doLock() })
	va.lockBtn.Importance = widget.DangerImportance
	va.lockBtn.Disable()

	va.newNoteBtn = widget.NewButton("New Note", func() { va.doNewNote() })
	va.newNoteBtn.Disable()

	va.decryptBtn = widget.NewButton("Decrypt…", func() { va.doDecrypt() })
	va.decryptBtn.Disable()
	va.editBtn = widget.NewButton("Edit…", func() { go va.doEditEntry() })
	va.editBtn.Disable()
	va.selectAllBtn = widget.NewButton("Select All", func() { va.doSelectAll() })
	va.selectAllBtn.Disable()
	va.deleteBtn = widget.NewButton("Delete", func() { va.doDelete() })
	va.deleteBtn.Disable()
	va.importBtn = widget.NewButton("Import File…", func() { go va.doImport() })
	va.importBtn.Disable()
	refreshBtn := widget.NewButton("Refresh", func() { va.doRefresh() })

	return widget.NewToolbar(
		&toolbarWidget{va.createBtn},
		&toolbarWidget{va.openBtn},
		widget.NewToolbarSeparator(),
		&toolbarWidget{va.lockBtn},
		widget.NewToolbarSpacer(),
		&toolbarWidget{va.newNoteBtn},
		widget.NewToolbarSeparator(),
		&toolbarWidget{va.importBtn},
		&toolbarWidget{va.decryptBtn},
		&toolbarWidget{va.editBtn},
		widget.NewToolbarSeparator(),
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
		entryPath := ""
		if id.Row >= 0 && id.Row < len(va.entries) {
			entryPath = va.entries[id.Row].VaultRelPath
		}
		va.mu.Unlock()
		va.decryptBtn.Enable()
		va.deleteBtn.Enable()
		// Edit button is only available for recognised text-format entries.
		if va.editBtn != nil && isTextEntry(entryPath) {
			va.editBtn.Enable()
		}
	}
	tbl.OnUnselected = func(_ widget.TableCellID) {
		va.mu.Lock()
		va.selected = -1
		count := len(va.selectedRows)
		va.mu.Unlock()
		va.decryptBtn.Disable()
		if va.editBtn != nil {
			va.editBtn.Disable()
		}
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
	desk.SetSystemTrayIcon(iconVaultPNG)
	desk.SetSystemTrayMenu(fyne.NewMenu("nexvault",
		fyne.NewMenuItem("Show nexvault", func() {
			va.win.Show()
			va.win.RequestFocus()
		}),
		fyne.NewMenuItem("New Encrypted Note", func() {
			va.win.Show()
			va.win.RequestFocus()
			fyne.Do(func() { va.doNewNote() })
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Lock Vault", func() { go va.doLock() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { go va.doLockAndQuit() }),
	))
}

// ── Vault operations ──────────────────────────────────────────────────────────

// showCreateDialog presents a form for choosing vault dir, drop dir, and password.
func (va *vaultApp) showCreateDialog() {
	vaultEntry := widget.NewEntry()
	vaultEntry.SetPlaceHolder("Type or paste path, or click Browse…")
	vaultEntry.SetText(defaultVaultDir(va.app))
	dropEntry := widget.NewEntry()
	dropEntry.SetPlaceHolder("Type or paste path, or click Browse…")
	dropEntry.SetText(defaultDropDir(va.app))

	vaultPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderNewIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			vaultEntry.SetText(u.Path())
		}, va.win)
	})
	dropPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			dropEntry.SetText(u.Path())
		}, va.win)
	})

	pass1 := widget.NewPasswordEntry()
	pass1.SetPlaceHolder("New password")
	pass2 := widget.NewPasswordEntry()
	pass2.SetPlaceHolder("Confirm password")

	var vaultHintText string
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		vaultHintText = "After creation the vault folder is hidden from the OS file " +
			"browser (macOS/Windows).\nNote its full path so you can open it by typing it here next time."
	} else {
		vaultHintText = "Note the full path to this folder — you will need to type it here to open it later."
	}
	vaultHint := widget.NewLabel(vaultHintText)
	vaultHint.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(
		widget.NewLabelWithStyle("Vault Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, vaultPickBtn, vaultEntry),
		vaultHint,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Drop Folder (auto-encrypt incoming files)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, dropPickBtn, dropEntry),
		dropFolderWarning(),
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
			vaultDir := strings.TrimSpace(vaultEntry.Text)
			dropDir := strings.TrimSpace(dropEntry.Text)
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
	d.Resize(fyne.NewSize(560, 0))
	d.Show()
}

func (va *vaultApp) doCreate(vaultDir, dropDir, pass string) {
	if err := vault.CreateVault(vaultDir, pass); err != nil {
		va.showErrorOnMain("Create vault", err)
		return
	}
	// Show the vault path so the user can note it — the folder is hidden from
	// the OS file browser (macOS/Windows), so the path is the only way to find it.
	fyne.Do(func() {
		dialog.ShowInformation("Vault Created",
			fmt.Sprintf("Vault created successfully.\n\nVault path (note this down):\n%s\n\nThe path is also saved for the next time you open the app.", vaultDir),
			va.win)
	})
	va.startSession(vaultDir, dropDir, pass)
}

// showOpenDialog presents a form for choosing an existing vault dir, drop dir,
// and the unlock password.
func (va *vaultApp) showOpenDialog() {
	vaultEntry := widget.NewEntry()
	vaultEntry.SetPlaceHolder("Type or paste path, or click Browse…")
	vaultEntry.SetText(defaultVaultDir(va.app))
	dropEntry := widget.NewEntry()
	dropEntry.SetPlaceHolder("Type or paste path, or click Browse…")
	dropEntry.SetText(defaultDropDir(va.app))

	vaultPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			vaultEntry.SetText(u.Path())
		}, va.win)
	})
	dropPickBtn := widget.NewButtonWithIcon("Browse…", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			dropEntry.SetText(u.Path())
		}, va.win)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Vault password")

	var vaultHintText string
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		vaultHintText = "The vault folder is hidden from the OS file browser (macOS/Windows) " +
			"and cannot be found with Browse. Type or paste its full path. " +
			"The path was shown when the vault was created and is pre-filled here if this device has opened it before."
	} else {
		vaultHintText = "Type the full path to the vault folder, or use Browse to navigate to it."
	}
	vaultHint := widget.NewLabel(vaultHintText)
	vaultHint.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(
		widget.NewLabelWithStyle("Vault Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, vaultPickBtn, vaultEntry),
		vaultHint,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Drop Folder (optional)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, dropPickBtn, dropEntry),
		widget.NewLabel("Leave blank to open without auto-encrypt. Every file\nsaved here is encrypted into the vault and deleted from disk."),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		passEntry,
	)

	d := dialog.NewCustomConfirm("Open Vault", "Open", "Cancel", form,
		func(ok bool) {
			if !ok {
				return
			}
			vaultDir := strings.TrimSpace(vaultEntry.Text)
			if vaultDir == "" {
				dialog.ShowError(fmt.Errorf("vault folder is required"), va.win)
				return
			}
			dropDir := strings.TrimSpace(dropEntry.Text)
			go va.startSession(vaultDir, dropDir, passEntry.Text)
		}, va.win)
	d.Resize(fyne.NewSize(560, 0))
	d.Show()
}

// startSession unlocks the vault and, if a drop folder is given, starts the
// file watcher. If dropDir is empty the vault opens without auto-encrypt.
func (va *vaultApp) startSession(vaultDir, dropDir, pass string) {
	sess := new(vault.Session)
	if err := vault.UnlockVault(sess, vaultDir, pass); err != nil {
		va.showErrorOnMain("Unlock failed", err)
		return
	}

	// Persist both paths immediately after a successful unlock so the Open
	// dialog pre-fills them on the next launch. This is especially important
	// on macOS where the vault folder is hidden (UF_HIDDEN) and cannot be
	// found via the file picker.
	saveLastPaths(va.app, vaultDir, dropDir)

	var w *watcher.Watcher
	if dropDir != "" {
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

		var err error
		w, err = watcher.New(sess, dropDir, logFn)
		if err != nil {
			va.showErrorOnMain("Watcher init", err)
			return
		}
		if err := w.Start(); err != nil {
			va.showErrorOnMain("Watcher start", err)
			return
		}
	}

	va.mu.Lock()
	va.session = sess
	va.vaultPath = vaultDir
	va.dropPath = dropDir
	va.w = w
	// (Re-)start the auto-lock countdown. Cancel any previous timer first in
	// case startSession is called while a vault is already open.
	if va.autoLockTimer != nil {
		va.autoLockTimer.Stop()
	}
	va.sessionGen++
	thisGen := va.sessionGen
	va.autoLockTimer = time.AfterFunc(autoLockDuration, func() {
		// Guard against the narrow race where a new session is started between
		// the timer firing and this callback executing: if the generation has
		// advanced, a newer session is active and we must not lock it.
		va.mu.Lock()
		valid := va.sessionGen == thisGen
		va.mu.Unlock()
		if valid {
			va.doLock()
		}
	})
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
	t := va.autoLockTimer
	va.w = nil
	va.session = nil
	va.vaultPath = ""
	va.dropPath = ""
	va.entries = nil
	va.selected = -1
	va.selectedRows = make(map[int]bool)
	va.autoLockTimer = nil
	va.sessionGen++ // Invalidate any pending auto-lock timer for this session.
	va.mu.Unlock()

	// Stop the auto-lock countdown so it does not fire a second time after a
	// manual lock (the CAS guard above would swallow it, but stopping the
	// timer avoids the unnecessary goroutine wakeup).
	if t != nil {
		t.Stop()
	}

	// Disable interactive controls immediately so the user cannot trigger
	// another lock (or decrypt/delete) while the watcher is still draining.
	// This must happen before w.Stop() because Stop() blocks until all
	// pending files have been encrypted.
	fyne.Do(func() {
		va.lockBtn.Disable()
		va.newNoteBtn.Disable()
		va.decryptBtn.Disable()
		va.editBtn.Disable()
		va.deleteBtn.Disable()
		va.selectAllBtn.Disable()
		va.importBtn.Disable()
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

// doLockAndHide locks the vault and then hides the window.
// It is used by the window close-button intercept: the vault is always in a
// locked state when the window is not visible.
func (va *vaultApp) doLockAndHide() {
	va.doLock()
	fyne.Do(func() { va.win.Hide() })
}

// doLockAndQuit locks the vault (draining any in-flight encryptions) and then
// terminates the application. It is the safe Quit path from the tray menu.
func (va *vaultApp) doLockAndQuit() {
	va.doLock()
	va.app.Quit()
}

// setLocked adjusts which toolbar buttons are enabled.
// Safe to call from any goroutine.
func (va *vaultApp) setLocked(locked bool) {
	fyne.Do(func() {
		if locked {
			va.lockBtn.Disable()
			va.newNoteBtn.Disable()
			va.decryptBtn.Disable()
			va.editBtn.Disable()
			va.deleteBtn.Disable()
			va.selectAllBtn.Disable()
			va.selectAllBtn.SetText("Select All")
			va.importBtn.Disable()
		} else {
			va.lockBtn.Enable()
			va.newNoteBtn.Enable()
			va.selectAllBtn.Enable()
			va.importBtn.Enable()
			// editBtn is only enabled when a text entry is selected
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
		} else if dp == "" {
			text = fmt.Sprintf("Status: unlocked  •  Vault: %s  •  (no drop folder — use New Note or Import to add files)", vp)
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
	va.mu.Unlock()

	// Clear the checkbox selection on the UI goroutine so that it is
	// serialised with doSelectAll(), which also runs on the UI goroutine.
	// Moving the clear into fyne.Do eliminates the race where the goroutine
	// cleared selectedRows between doSelectAll's mutex unlock and its
	// table.Refresh() call, causing the button to say "Deselect All" while
	// the table rendered with an empty selection map.
	fyne.Do(func() {
		va.mu.Lock()
		va.selectedRows = make(map[int]bool)
		va.mu.Unlock()
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
// Must be called from the Fyne event goroutine (button OnTapped callback).
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
	sel := va.selected
	va.mu.Unlock()

	// Called from the Fyne button callback — already on the UI goroutine.
	// Update the table and controls directly; no fyne.Do() needed here.
	va.table.Refresh()
	if count > 0 {
		va.deleteBtn.Enable()
		va.selectAllBtn.SetText("Deselect All")
	} else {
		va.selectAllBtn.SetText("Select All")
		if sel < 0 {
			va.deleteBtn.Disable()
		}
	}
}

// ── Import ────────────────────────────────────────────────────────────────────

// doImport opens a file picker and encrypts the chosen file directly into the
// active vault. This is the primary way to add files on Android and iOS (where
// the drop-folder watcher is a no-op) and a convenient alternative on desktop.
func (va *vaultApp) doImport() {
	va.mu.Lock()
	sess := va.session
	va.mu.Unlock()
	if sess == nil {
		return
	}

	d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		vRel := r.URI().Name()
		go func() {
			defer r.Close()
			if encErr := vault.UpsertStreamToVault(sess, vRel, r, -1); encErr != nil {
				va.showErrorOnMain("Import failed", encErr)
				return
			}
			va.showInfoOnMain("Imported", fmt.Sprintf("Encrypted and stored:\n%s", vRel))
			if va.refreshPending.CompareAndSwap(false, true) {
				go func() {
					defer va.refreshPending.Store(false)
					va.refreshEntries()
				}()
			}
		}()
	}, va.win)
	d.Show()
}

// ── Built-in text editor ──────────────────────────────────────────────────────

// isTextEntry reports whether the vault entry at name is a text format that
// the built-in editor can open.
func isTextEntry(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".md", ".markdown", ".log", ".csv",
		".json", ".xml", ".yaml", ".yml", ".toml",
		".ini", ".cfg", ".conf":
		return true
	}
	return false
}

// doNewNote opens a built-in text editor dialog so the user can compose a note
// and encrypt it directly into the vault without using the drop folder.
func (va *vaultApp) doNewNote() {
	va.mu.Lock()
	sess := va.session
	va.mu.Unlock()
	if sess == nil {
		return
	}

	nameEntry := widget.NewEntry()
	nameEntry.SetText("note.txt")
	nameEntry.SetPlaceHolder("filename (e.g. note.txt)")

	textEntry := widget.NewMultiLineEntry()
	textEntry.SetPlaceHolder("Type your note here…")
	textEntry.Wrapping = fyne.TextWrapWord

	form := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("Filename", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			nameEntry,
			widget.NewSeparator(),
			widget.NewLabelWithStyle("Content", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		),
		nil, nil, nil,
		textEntry,
	)

	d := dialog.NewCustomConfirm("New Text Note", "Save to Vault", "Cancel", form,
		func(ok bool) {
			if !ok {
				return
			}
			name := strings.TrimSpace(nameEntry.Text)
			if name == "" {
				dialog.ShowError(fmt.Errorf("filename is required"), va.win)
				return
			}
			text := textEntry.Text
			go func() {
				data := []byte(text)
				if err := vault.UpsertStreamToVault(sess, name, bytes.NewReader(data), int64(len(data))); err != nil {
					va.showErrorOnMain("Save note", err)
					return
				}
				va.showInfoOnMain("Note saved", fmt.Sprintf("Encrypted and stored:\n%s", name))
				if va.refreshPending.CompareAndSwap(false, true) {
					go func() {
						defer va.refreshPending.Store(false)
						va.refreshEntries()
					}()
				}
			}()
		}, va.win)
	d.Resize(fyne.NewSize(640, 480))
	d.Show()
}

// doEditEntry decrypts the selected text entry and opens it in the built-in
// editor. On save the modified content is re-encrypted into the vault.
func (va *vaultApp) doEditEntry() {
	va.mu.Lock()
	sel := va.selected
	entries := va.entries
	sess := va.session
	va.mu.Unlock()

	if sel < 0 || sel >= len(entries) || sess == nil {
		return
	}
	entry := entries[sel]

	const maxTextSize = 10 << 20 // 10 MB

	var buf bytes.Buffer
	buf.Grow(int(min(entry.Size+1, int64(maxTextSize))))
	if _, err := vault.DecryptToWriterByVaultPath(sess, entry.VaultRelPath, &buf); err != nil {
		va.showErrorOnMain("Open entry", err)
		return
	}
	if buf.Len() > maxTextSize {
		va.showErrorOnMain("Open entry",
			fmt.Errorf("file is too large for the built-in editor (%s)", guiFormatSize(int64(buf.Len()))))
		return
	}
	text := buf.String()
	fyne.Do(func() { va.showTextEditorDialog(entry.VaultRelPath, text, sess) })
}

// showTextEditorDialog presents an editable text area for vaultRelPath. On
// save the content is re-encrypted into the vault via UpsertStreamToVault.
func (va *vaultApp) showTextEditorDialog(vaultRelPath, initialText string, sess *vault.Session) {
	textEntry := widget.NewMultiLineEntry()
	textEntry.SetText(initialText)
	textEntry.Wrapping = fyne.TextWrapWord

	d := dialog.NewCustomConfirm(
		"Edit: "+filepath.Base(vaultRelPath),
		"Save to Vault", "Cancel",
		textEntry,
		func(ok bool) {
			if !ok {
				return
			}
			text := textEntry.Text
			go func() {
				data := []byte(text)
				if err := vault.UpsertStreamToVault(sess, vaultRelPath, bytes.NewReader(data), int64(len(data))); err != nil {
					va.showErrorOnMain("Save failed", err)
					return
				}
				if va.refreshPending.CompareAndSwap(false, true) {
					go func() {
						defer va.refreshPending.Store(false)
						va.refreshEntries()
					}()
				}
			}()
		}, va.win)
	d.Resize(fyne.NewSize(720, 540))
	d.Show()
}



func (va *vaultApp) showErrorOnMain(ctx string, err error) {
	// dialog.ShowError queues itself on the main thread internally.
	dialog.ShowError(fmt.Errorf("%s: %w", ctx, err), va.win)
}

func (va *vaultApp) showInfoOnMain(title, msg string) {
	dialog.ShowInformation(title, msg, va.win)
}

// dropFolderWarning returns a label widget that explains the auto-encrypt-and-
// delete behaviour of the drop folder, used in the Create and Open dialogs.
func dropFolderWarning() *widget.Label {
	return widget.NewLabel("⚠️  Use a dedicated folder. Every file saved here is automatically\nencrypted into the vault and permanently deleted from disk.")
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

