//go:build !android && !ios

// This file contains the text-based CLI for nexvault. It is excluded from
// Android and iOS builds, where only the Fyne GUI is available.
package ui

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"nexvault/internal/vault"
	"nexvault/internal/watcher"
)

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
