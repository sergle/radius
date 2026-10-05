// dictload loads FreeRADIUS-style dictionaries and reports warnings and errors,
// e.g. to check a FreeRADIUS installation: dictload /usr/share/freeradius/dictionary
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/sergle/radius/v2"
)

func main() {
	debug := flag.Bool("debug", false, "Also log ignored definitions")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-debug] dictionary...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	level := slog.LevelWarn
	if *debug {
		level = slog.LevelDebug
	}
	radius.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	failed := false
	for _, path := range flag.Args() {
		if err := radius.NewDictionary().LoadFile(path); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Printf("%s: OK\n", path)
	}
	if failed {
		os.Exit(1)
	}
}
