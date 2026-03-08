package ui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"nexvault/internal/vault"
)

type AppUI struct {
	window    fyne.Window
	content   *fyne.Container
	logWidget *widget.Entry
	app       fyne.App

	vaultPath string
	session   vault.Session
}

func (ui *AppUI) log(msg string) {
	ui.logWidget.SetText(ui.logWidget.Text + "[" + time.Now().Format("15:04:05") + "] " + msg + "\n")
	ui.logWidget.CursorRow = len(strings.Split(ui.logWidget.Text, "\n"))
}

func Run() {
	a := app.NewWithID("com.0x4e4558.vault")
	w := a.NewWindow("0x4E4558vault")
	w.Resize(fyne.NewSize(860, 600))

	ui := &AppUI{
		window:  w,
		content: container.NewStack(),
		logWidget: func() *widget.Entry {
			e := widget.NewMultiLineEntry()
			e.Disable()
			return e
		}(),
		app: a,
	}

	ui.showMain()

	split := container.NewVSplit(ui.content, ui.logWidget)
	split.Offset = 0.82
	w.SetContent(split)

	w.SetCloseIntercept(func() {
		ui.session.LockAndWipe()
		ui.log("Session terminated. Keys wiped.")
		a.Quit()
	})

	w.ShowAndRun()
}

// ---------- Screens ----------

func (ui *AppUI) showMain() {
	dirLabel := widget.NewLabel("No vault linked.")
	pass := widget.NewPasswordEntry()

	ui.content.Objects = []fyne.CanvasObject{
		container.NewVBox(
			widget.NewLabelWithStyle("0x4E4558 Sovereign Engine", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			dirLabel,
			widget.NewButton("Link Vault Folder", func() {
				dialog.ShowFolderOpen(func(lu fyne.ListableURI, e error) {
					if e != nil {
						dialog.ShowError(e, ui.window)
						return
					}
					if lu != nil {
						ui.vaultPath = lu.Path()
						dirLabel.SetText(ui.vaultPath)
						ui.log("Linked: " + ui.vaultPath)
					}
				}, ui.window)
			}),
			pass,
			container.NewGridWithColumns(2,
				widget.NewButton("Unlock", func() {
					if err := vault.UnlockVault(&ui.session, ui.vaultPath, pass.Text); err == nil {
						pass.SetText("")
						ui.log("Vault unlocked.")
						ui.showUnlocked()
					} else {
						dialog.ShowError(err, ui.window)
					}
				}),
				widget.NewButton("Create", func() {
					if err := vault.CreateVault(ui.vaultPath, pass.Text); err != nil {
						dialog.ShowError(err, ui.window)
						return
					}
					pass.SetText("")
					ui.log("Vault created at: " + ui.vaultPath)
				}),
			),
		),
	}
	ui.content.Refresh()
}

func (ui *AppUI) showUnlocked() {
	ui.content.Objects = []fyne.CanvasObject{
		container.NewVBox(
			widget.NewLabelWithStyle("Vault Operations", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			container.NewGridWithColumns(2,
				widget.NewButton("Import New", func() { ui.importOne(false) }),
				widget.NewButton("Replace", func() { ui.importOne(true) }),
			),
			container.NewGridWithColumns(2,
				widget.NewButton("Import Directory", ui.importDirectory),
				widget.NewButton("Browse Index", ui.showBrowse),
			),
			widget.NewButton("Lock", func() {
				ui.session.LockAndWipe()
				ui.log("Vault locked.")
				ui.showMain()
			}),
		),
	}
	ui.content.Refresh()
}

func (ui *AppUI) importOne(replace bool) {
	dialog.ShowFileOpen(func(rc fyne.URIReadCloser, e error) {
		if e != nil {
			dialog.ShowError(e, ui.window)
			return
		}
		if rc == nil {
			return
		}
		u := rc.URI()
		_ = rc.Close()
		if u == nil {
			dialog.ShowError(fmt.Errorf("invalid URI"), ui.window)
			return
		}

		defaultName := "import.bin"
		if u.Name() != "" {
			defaultName = filepath.Base(u.Name())
		}

		vPath := widget.NewEntry()
		vPath.SetText(defaultName)

		title := "Import as Vault Path"
		if replace {
			title = "Replace Vault Path (Explicit)"
		}

		doImport := func(vRel string, replace bool) {
			r, err := storage.Reader(u)
			if err != nil {
				dialog.ShowError(err, ui.window)
				return
			}
			defer func() { _ = r.Close() }()

			if err := vault.PutStreamToVault(&ui.session, vRel, r, -1, replace); err != nil {
				dialog.ShowError(err, ui.window)
				return
			}
			if replace {
				ui.log("[REPLACED] " + vRel)
			} else {
				ui.log("[IMPORTED] " + vRel)
			}
		}

		dialog.ShowForm(title, "OK", "Cancel",
			[]*widget.FormItem{widget.NewFormItem("Vault Path", vPath)},
			func(ok bool) {
				if !ok {
					return
				}
				vRel := strings.TrimSpace(vPath.Text)
				if vRel == "" {
					dialog.ShowError(fmt.Errorf("vault path cannot be empty"), ui.window)
					return
				}

				if replace {
					dialog.NewConfirm("Confirm Replace",
						"Replace entry at:\n\n"+vRel+"\n\nOld blob will be deleted after commit.",
						func(confirmed bool) {
							if !confirmed {
								return
							}
							doImport(vRel, true)
						}, ui.window).Show()
					return
				}

				doImport(vRel, false)
			}, ui.window)
	}, ui.window)
}

func (ui *AppUI) importDirectory() {
	dialog.ShowFolderOpen(func(lu fyne.ListableURI, e error) {
		if e != nil {
			dialog.ShowError(e, ui.window)
			return
		}
		if lu == nil {
			return
		}
		root := lu.Path()

		dialog.NewConfirm("On name collision",
			"If a file already exists in the vault, do you want to REPLACE it?\n\nYes = replace existing\nNo = skip existing\n\n(Non-existing entries are always created.)",
			func(replaceExisting bool) {
				policy := vault.DirImportSkipExisting
				if replaceExisting {
					policy = vault.DirImportReplaceExisting
				}

				cancel := &atomic.Bool{}
				progress := &vault.DirImportProgress{}
				progress.SetCurrent("")

				title := widget.NewLabel("Importing directory…")
				current := widget.NewLabel("")
				stats := widget.NewLabel("")
				cancelBtn := widget.NewButton("Cancel", func() { cancel.Store(true) })

				dlg := dialog.NewCustomWithoutButtons("Directory Import", container.NewVBox(
					title,
					widget.NewSeparator(),
					widget.NewLabel("Current file:"),
					current,
					widget.NewSeparator(),
					stats,
					cancelBtn,
				), ui.window)
				dlg.Show()

				stopUI := make(chan struct{})
				go func() {
					t := time.NewTicker(250 * time.Millisecond)
					defer t.Stop()
					for {
						select {
						case <-t.C:
							cur := progress.Current()
							current.SetText(cur)
							stats.SetText(fmt.Sprintf("Seen: %d | Imported: %d | Skipped: %d | Errors: %d",
								atomic.LoadInt64(&progress.FilesSeen),
								atomic.LoadInt64(&progress.FilesImported),
								atomic.LoadInt64(&progress.FilesSkipped),
								atomic.LoadInt64(&progress.Errors),
							))
							current.Refresh()
							stats.Refresh()
						case <-stopUI:
							return
						}
					}
				}()

				go func() {
					err := vault.ImportDirectory(&ui.session, root, policy, cancel, progress)

					close(stopUI)
					dlg.Hide()
					if err != nil && err.Error() != "cancelled" {
						dialog.ShowError(err, ui.window)
						return
					}
					if cancel.Load() {
						ui.log("[DIR IMPORT] cancelled")
					} else {
						ui.log(fmt.Sprintf("[DIR IMPORT] done: seen=%d imported=%d skipped=%d errors=%d",
							atomic.LoadInt64(&progress.FilesSeen),
							atomic.LoadInt64(&progress.FilesImported),
							atomic.LoadInt64(&progress.FilesSkipped),
							atomic.LoadInt64(&progress.Errors),
						))
					}
				}()
			}, ui.window).Show()
	}, ui.window)
}

func (ui *AppUI) showBrowse() {
	idx, err := func() (vault.VaultIndex, error) {
		return vault.LoadIndexWithKey(filepath.Join(ui.session.VaultPath, "index.nexi"), ui.session.KIndex, ui.session.VaultID)
	}()
	if err != nil {
		dialog.ShowError(err, ui.window)
		return
	}

	entries := make([]vault.IndexEntry, len(idx.Entries))
	copy(entries, idx.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].VaultRelPath) < strings.ToLower(entries[j].VaultRelPath)
	})

	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("Filter (substring match), e.g. report or docs/")

	filtered := make([]vault.IndexEntry, 0, len(entries))
	applyFilter := func(q string) {
		q = strings.ToLower(strings.TrimSpace(q))
		filtered = filtered[:0]
		if q == "" {
			filtered = append(filtered, entries...)
			return
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.VaultRelPath), q) {
				filtered = append(filtered, e)
			}
		}
	}
	applyFilter("")

	list := widget.NewList(
		func() int { return len(filtered) },
		func() fyne.CanvasObject {
			pathLbl := widget.NewLabel("")
			metaLbl := widget.NewLabel("")
			metaLbl.TextStyle = fyne.TextStyle{Italic: true}
			metaLbl.Wrapping = fyne.TextWrapWord
			return container.NewVBox(pathLbl, metaLbl)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			pathLbl := box.Objects[0].(*widget.Label)
			metaLbl := box.Objects[1].(*widget.Label)
			e := filtered[i]
			pathLbl.SetText(e.VaultRelPath)
			metaLbl.SetText(fmt.Sprintf("Size: %d bytes | Gen: %d", e.Size, e.Gen))
		},
	)

	filterEntry.OnChanged = func(s string) {
		applyFilter(s)
		list.Refresh()
	}

	var selected *vault.IndexEntry
	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filtered) {
			selected = nil
			return
		}
		e := filtered[id]
		selected = &e
	}

	decryptSelected := widget.NewButton("Decrypt Selected (Save As…)", func() {
		if selected == nil {
			dialog.ShowInformation("No selection", "Select an entry first.", ui.window)
			return
		}

		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, e error) {
			if e != nil {
				dialog.ShowError(e, ui.window)
				return
			}
			if wc == nil {
				return
			}
			defer func() { _ = wc.Close() }()

			n, err := vault.DecryptToWriterByVaultPath(&ui.session, selected.VaultRelPath, wc)
			if err != nil {
				dialog.ShowError(err, ui.window)
				return
			}
			ui.log(fmt.Sprintf("[DECRYPTED] %s -> saved (%d bytes)", selected.VaultRelPath, n))
		}, ui.window)
	})

	deleteSelected := widget.NewButton("Delete Selected Entry", func() {
		if selected == nil {
			dialog.ShowInformation("No selection", "Select an entry first.", ui.window)
			return
		}
		msg := "Delete entry:\n\n" + selected.VaultRelPath + "\n\nThis removes it from the index and deletes its encrypted blob."
		dialog.NewConfirm("Confirm Delete", msg, func(ok bool) {
			if !ok {
				return
			}
			if err := vault.DeleteEntry(&ui.session, selected.VaultRelPath); err != nil {
				dialog.ShowError(err, ui.window)
				return
			}
			ui.log("[DELETED] " + selected.VaultRelPath)
			ui.showBrowse()
		}, ui.window).Show()
	})

	backBtn := widget.NewButton("Back", func() { ui.showUnlocked() })

	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(
			container.NewVBox(
				widget.NewLabelWithStyle("Vault Browser", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				filterEntry,
			),
			container.NewVBox(
				container.NewGridWithColumns(2, decryptSelected, deleteSelected),
				layout.NewSpacer(),
				backBtn,
			),
			nil,
			nil,
			container.NewVBox(list),
		),
	}
	ui.content.Refresh()
}
