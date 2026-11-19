// Command kofra is the command line for the Kofra API:
//
//	kofra <resource> <command> [args] [--flags]
//
// The token comes from KOFRA_API_TOKEN (never from a flag, so it stays out of
// shell history and process lists) and the address from KOFRA_API_URL.
// Exit codes: 0 success, 1 the API or the network failed, 2 usage error.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra"
)

// command is one API operation as a CLI command; the table is generated.
type command struct {
	resource, name, operation, summary, method, path string
	args, query                                      []string
	body, dryRun, destructive                        bool
}

const (
	exitOK    = 0
	exitAPI   = 1
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// invocation is the parsed command line.
type invocation struct {
	cmd      *command
	resource string
	args     []string
	query    url.Values
	body     string
	hasBody  bool
	json     bool
	dryRun   bool
	yes      bool
	help     bool
}

func run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(argv) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch argv[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case "version", "--version":
		fmt.Fprintf(stdout, "kofra %s\n", kofra.Version)
		return exitOK
	}
	inv, err := parse(argv)
	if err != nil {
		fmt.Fprintf(stderr, "kofra: %s\n", err)
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(stderr, "Run `kofra help` for the list of commands.")
		}
		return exitUsage
	}
	if inv.help {
		if inv.cmd == nil {
			fmt.Fprintln(stdout, resourceList(inv.resource))
		} else {
			commandUsage(stdout, inv.cmd)
		}
		return exitOK
	}
	if err := inv.check(); err != nil {
		fmt.Fprintf(stderr, "kofra: %s\n", err)
		return exitUsage
	}

	var body any
	if inv.cmd.body {
		raw, err := readBody(inv.body, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "kofra: %s\n", err)
			return exitUsage
		}
		body = raw
	}
	path := inv.cmd.path
	for i, name := range inv.cmd.args {
		path = strings.Replace(path, "{"+name+"}", url.PathEscape(inv.args[i]), 1)
	}
	if inv.dryRun {
		inv.query.Set("dry_run", "true")
	}

	client, err := kofra.New(kofra.WithToken(getenv("KOFRA_API_TOKEN")), kofra.WithBaseURL(getenv("KOFRA_API_URL")))
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		return exitUsage
	}
	out, err := client.Do(ctx, inv.cmd.method, path, inv.query, body)
	if err != nil {
		return reportError(err, inv.json, stdout, stderr)
	}
	if err := render(stdout, inv, out); err != nil {
		fmt.Fprintf(stderr, "kofra: %s\n", err)
		return exitAPI
	}
	return exitOK
}

func parse(argv []string) (*invocation, error) {
	inv := &invocation{query: url.Values{}}
	var words []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			words = append(words, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			words = append(words, a)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(argv) {
				return "", usagef("--%s needs a value", name)
			}
			i++
			return argv[i], nil
		}
		switch name {
		case "json":
			inv.json = true
		case "dry-run":
			inv.dryRun = true
		case "yes", "y":
			inv.yes = true
		case "help", "h":
			inv.help = true
		case "body":
			v, err := takeValue()
			if err != nil {
				return nil, err
			}
			inv.body, inv.hasBody = v, true
		default:
			v, err := takeValue()
			if err != nil {
				return nil, err
			}
			inv.query.Set(strings.ReplaceAll(name, "-", "_"), v)
		}
		if (name == "json" || name == "dry-run" || name == "yes" || name == "y" || name == "help" || name == "h") && hasValue {
			return nil, usagef("--%s takes no value", name)
		}
	}
	if len(words) == 0 {
		return nil, usagef("missing a resource")
	}
	resource := words[0]
	if !hasResource(resource) {
		return nil, usagef("unknown resource %q", resource)
	}
	if len(words) < 2 {
		if inv.help {
			inv.resource = resource
			return inv, nil
		}
		return nil, usagef("missing a command for %s\n%s", resource, resourceList(resource))
	}
	for i := range commands {
		if commands[i].resource == resource && commands[i].name == words[1] {
			inv.cmd = &commands[i]
		}
	}
	if inv.cmd == nil {
		return nil, usagef("unknown command %q for %s\n%s", words[1], resource, resourceList(resource))
	}
	inv.args = words[2:]
	return inv, nil
}

// check applies the rules that need the command: arguments, flags, --yes.
func (inv *invocation) check() error {
	c := inv.cmd
	if len(inv.args) != len(c.args) {
		return usagef("%s takes %d argument(s) (%s), got %d", cliName(c), len(c.args), argList(c), len(inv.args))
	}
	for name := range inv.query {
		known := false
		for _, q := range c.query {
			known = known || q == name
		}
		if !known {
			return usagef("%s has no flag --%s", cliName(c), strings.ReplaceAll(name, "_", "-"))
		}
	}
	if inv.hasBody && !c.body {
		return usagef("%s takes no --body", cliName(c))
	}
	if c.body && !inv.hasBody {
		return usagef("%s needs --body '<json>' (or --body @file, --body - for stdin)", cliName(c))
	}
	if inv.dryRun && !c.dryRun {
		return usagef("%s has no --dry-run", cliName(c))
	}
	if c.destructive && !inv.yes && !inv.dryRun {
		return usagef("%s cannot be undone; pass --yes to run it, or --dry-run to preview it", cliName(c))
	}
	return nil
}

func readBody(spec string, stdin io.Reader) (json.RawMessage, error) {
	var data []byte
	var err error
	switch {
	case spec == "-":
		data, err = io.ReadAll(io.LimitReader(stdin, 1<<20))
	case strings.HasPrefix(spec, "@"):
		data, err = os.ReadFile(spec[1:])
	default:
		data = []byte(spec)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the body: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, usagef("the body is not a JSON object: %v", err)
	}
	return json.RawMessage(data), nil
}

func reportError(err error, asJSON bool, stdout, stderr io.Writer) int {
	var kerr *kofra.Error
	if !errors.As(err, &kerr) {
		fmt.Fprintf(stderr, "kofra: %s\n", err)
		return exitAPI
	}
	p := kerr.Problem
	if asJSON {
		if b, jerr := json.MarshalIndent(p, "", "  "); jerr == nil {
			fmt.Fprintf(stdout, "%s\n", b)
		}
	}
	fmt.Fprintf(stderr, "error: %s (HTTP %d): %s\n", p.Code, kerr.Status, p.Detail)
	if p.Errors != nil {
		for _, e := range *p.Errors {
			fmt.Fprintf(stderr, "  %s: %s (%s)\n", e.Pointer, e.Detail, e.Code)
		}
	}
	fmt.Fprintf(stderr, "hint: %s\n", p.Hint)
	fmt.Fprintf(stderr, "request_id: %s\n", p.RequestId)
	return exitAPI
}

// render prints the answer: JSON with --json, otherwise a short text form.
func render(w io.Writer, inv *invocation, body []byte) error {
	if body == nil {
		if !inv.json {
			fmt.Fprintf(w, "Done: %s.\n", inv.cmd.summary)
		}
		return nil
	}
	if inv.json {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err != nil {
			return err
		}
		buf.WriteByte('\n')
		_, err := w.Write(buf.Bytes())
		return err
	}
	var v ordered
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	obj, ok := v.value.(*object)
	if !ok {
		fmt.Fprintln(w, scalar(v.value))
		return nil
	}
	if data, ok := obj.get("data"); ok {
		if items, ok := data.([]any); ok {
			table(w, items)
			if next, ok := obj.get("next_cursor"); ok && next != nil {
				fmt.Fprintf(w, "next_cursor: %v\n", scalar(next))
			}
			return nil
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	flatten(tw, "", obj)
	return tw.Flush()
}

// table prints a list with one row per item and a column per scalar field.
func table(w io.Writer, items []any) {
	if len(items) == 0 {
		fmt.Fprintln(w, "(none)")
		return
	}
	first, ok := items[0].(*object)
	if !ok {
		for _, it := range items {
			fmt.Fprintln(w, scalar(it))
		}
		return
	}
	var cols []string
	for i, k := range first.keys {
		if isScalar(first.values[i]) {
			cols = append(cols, k)
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.ToUpper(strings.Join(cols, "\t")))
	for _, it := range items {
		row := make([]string, len(cols))
		if o, ok := it.(*object); ok {
			for i, c := range cols {
				v, _ := o.get(c)
				row[i] = scalar(v)
			}
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
}

func flatten(w io.Writer, prefix string, v any) {
	switch t := v.(type) {
	case *object:
		for i, k := range t.keys {
			flatten(w, join(prefix, k), t.values[i])
		}
	case []any:
		if len(t) == 0 {
			fmt.Fprintf(w, "%s:\t(none)\n", prefix)
		}
		for i, e := range t {
			flatten(w, fmt.Sprintf("%s[%d]", prefix, i), e)
		}
	default:
		fmt.Fprintf(w, "%s:\t%s\n", prefix, scalar(t))
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func isScalar(v any) bool {
	switch v.(type) {
	case *object, []any:
		return false
	}
	return true
}

func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// object is a JSON object that keeps its key order, so output follows the contract.
type object struct {
	keys   []string
	values []any
}

func (o *object) get(k string) (any, bool) {
	for i, key := range o.keys {
		if key == k {
			return o.values[i], true
		}
	}
	return nil, false
}

type ordered struct{ value any }

func (o *ordered) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec)
	o.value = v
	return err
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			obj := &object{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, kt.(string))
				obj.values = append(obj.values, val)
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			_, err := dec.Token()
			return arr, err
		}
	}
	return tok, nil
}

// ---------------------------------------------------------------- help

func cliName(c *command) string { return "kofra " + c.resource + " " + c.name }

func argList(c *command) string {
	if len(c.args) == 0 {
		return "none"
	}
	return "<" + strings.Join(c.args, "> <") + ">"
}

func hasResource(r string) bool {
	for _, c := range commands {
		if c.resource == r {
			return true
		}
	}
	return false
}

func resourceList(r string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Commands for %s:\n", r)
	for _, c := range commands {
		if c.resource == r {
			fmt.Fprintf(&b, "  %-16s %s\n", c.name, c.summary)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: kofra <resource> <command> [args] [--flags]

Set KOFRA_API_TOKEN to an API token (and KOFRA_API_URL to use another address).

Flags for every command:
  --json      print the API's JSON answer
  --dry-run   preview a change without making it (where offered)
  --yes       confirm a command that cannot be undone; kofra never prompts
  --help      help for a command

Commands:
`)
	var resources []string
	for _, c := range commands {
		if !hasString(resources, c.resource) {
			resources = append(resources, c.resource)
		}
	}
	sort.Strings(resources)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, r := range resources {
		for _, c := range commands {
			if c.resource == r {
				args := ""
				if len(c.args) > 0 {
					args = " " + argList(&c)
				}
				fmt.Fprintf(tw, "  kofra %s %s%s\t%s\n", c.resource, c.name, args, c.summary)
			}
		}
	}
	_ = tw.Flush()
	fmt.Fprintln(w, "\nExit codes: 0 success, 1 API or network error, 2 usage error.")
}

func commandUsage(w io.Writer, c *command) {
	args := ""
	if len(c.args) > 0 {
		args = " " + argList(c)
	}
	fmt.Fprintf(w, "Usage: %s%s [--flags]\n\n%s. Operation %s (%s %s).\n\nFlags:\n", cliName(c), args, c.summary, c.operation, c.method, c.path)
	for _, q := range c.query {
		fmt.Fprintf(w, "  --%s <value>\n", strings.ReplaceAll(q, "_", "-"))
	}
	if c.body {
		fmt.Fprintln(w, "  --body <json>  the request body: inline JSON, @file, or - for stdin")
	}
	if c.dryRun {
		fmt.Fprintln(w, "  --dry-run      preview the change without making it")
	}
	if c.destructive {
		fmt.Fprintln(w, "  --yes          required: this cannot be undone")
	}
	fmt.Fprintln(w, "  --json         print the API's JSON answer")
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
