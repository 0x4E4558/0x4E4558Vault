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

// Run is the CLI entry point.
func Run() {
	if len(os.Args) < 2 {
		usage()
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
		usage()
	default:
		fmt.Fprintf(os.Stderr, "nexvault: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nexvault — encrypted file vault

usage:
  nexvault <command> [flags]

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

run 'nexvault <command> -h' for per-command help.
`)
}

// ── create ───────────────────────────────────────────────────────────────────

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	mustParse(fs, args)
	requireFlag("create", "-vault", *vaultDir)

	pass, err := readNewPassword()
	die(err)
	die(vault.CreateVault(*vaultDir, pass))
	fmt.Printf("vault created: %s\n", *vaultDir)
}

// ── watch ────────────────────────────────────────────────────────────────────

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	dropDir := fs.String("drop", "", "folder to watch for incoming files (required)")
	mustParse(fs, args)
	requireFlag("watch", "-vault", *vaultDir)
	requireFlag("watch", "-drop", *dropDir)

	pass, err := readPassword("vault password: ")
	die(err)

	var sess vault.Session
	die(withMsg(vault.UnlockVault(&sess, *vaultDir, pass), "unlock failed"))
	fmt.Println("vault unlocked.")

	die(os.MkdirAll(*dropDir, 0700))

	logFn := func(msg string) {
		fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
	}

	w, err := watcher.New(&sess, *dropDir, logFn)
	die(err)
	die(withMsg(w.Start(), "watcher failed to start"))

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
	mustParse(fs, args)
	requireFlag("list", "-vault", *vaultDir)

	sess := openSession(*vaultDir)
	defer sess.LockAndWipe()

	idx, err := vault.LoadIndexForSession(sess)
	die(err)

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
			e.VaultRelPath,
			e.Size,
			e.Gen,
			time.Unix(e.Added, 0).Format("2006-01-02 15:04"),
		)
	}
	_ = tw.Flush()
}

// ── decrypt ──────────────────────────────────────────────────────────────────

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	entry := fs.String("entry", "", "vault-relative entry path (required)")
	outPath := fs.String("out", "", "output file path (required)")
	mustParse(fs, args)
	requireFlag("decrypt", "-vault", *vaultDir)
	requireFlag("decrypt", "-entry", *entry)
	requireFlag("decrypt", "-out", *outPath)

	sess := openSession(*vaultDir)
	defer sess.LockAndWipe()

	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	die(err)
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(*outPath)
		}
	}()

	n, err := vault.DecryptToWriterByVaultPath(sess, *entry, out)
	die(err)
	ok = true
	fmt.Printf("decrypted: %s -> %s (%d bytes)\n", *entry, *outPath, n)
}

// ── delete ───────────────────────────────────────────────────────────────────

func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	vaultDir := fs.String("vault", "", "vault directory (required)")
	entry := fs.String("entry", "", "vault-relative entry path (required)")
	mustParse(fs, args)
	requireFlag("delete", "-vault", *vaultDir)
	requireFlag("delete", "-entry", *entry)

	sess := openSession(*vaultDir)
	defer sess.LockAndWipe()

	fmt.Printf("delete %q from vault? [y/N] ", *entry)
	if !confirmYN() {
		fmt.Println("aborted.")
		return
	}

	die(vault.DeleteEntry(sess, *entry))
	fmt.Printf("deleted: %s\n", *entry)
}

// ── shared helpers ───────────────────────────────────────────────────────────

// stdinReader is a single shared reader for non-terminal stdin to avoid
// buffering issues that arise from creating multiple bufio.Reader instances
// over the same underlying os.Stdin file descriptor.
// All CLI commands that read from stdin do so sequentially (the watcher
// goroutine never calls readPassword), so no mutex is required.
var stdinReader = bufio.NewReader(os.Stdin)

// openSession prompts for the vault password and returns an unlocked session.
func openSession(vaultDir string) *vault.Session {
	pass, err := readPassword("vault password: ")
	die(err)
	sess := new(vault.Session)
	die(withMsg(vault.UnlockVault(sess, vaultDir, pass), "unlock failed"))
	return sess
}

// readPassword prints prompt to stderr, reads one line from stdin with echo
// disabled when stdin is a terminal.
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // restore newline suppressed by ReadPassword
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// Non-interactive stdin (piped password): use the shared reader.
	line, err := stdinReader.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// readNewPassword prompts twice and verifies the two entries match.
func readNewPassword() (string, error) {
	p1, err := readPassword("new vault password: ")
	if err != nil {
		return "", err
	}
	p2, err := readPassword("confirm password:    ")
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

// confirmYN reads a line from stdin and returns true for "y" or "yes".
func confirmYN() bool {
	line, _ := stdinReader.ReadString('\n')
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes"
}

func die(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexvault: %v\n", err)
		os.Exit(1)
	}
}

func withMsg(err error, msg string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

func mustParse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		die(err)
	}
}

func requireFlag(cmd, flagName, val string) {
	if val == "" {
		fmt.Fprintf(os.Stderr, "nexvault %s: %s is required\n", cmd, flagName)
		os.Exit(1)
	}
}

