package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	
	"qxss/internal/scanner"
	"qxss/internal/config"
	"qxss/internal/load"
	"qxss/internal/worker"
)

func parseFlags(args []string, stderr io.Writer) (config.Options, error) {
	var opts config.Options

	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&opts.Input, "input", "", "file with one URL per line (default: read stdin)")
	fs.IntVar(&opts.Workers, "workers", 8, "concurrent workers")
	fs.Float64Var(&opts.Rate, "rate", 10, "rate limit request per second")
	fs.StringVar(&opts.Payload, "payload", "", "file with one XSS payload per line (default: read stdin)")
	fs.BoolVar(&opts.FuzzPayload, "fuzz-payload", false, "switch to payload fuzzing, skip character probes (default: false)")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: ./qxss [flags]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return config.Options{}, err
	}

	return opts, nil
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	log := newLogger(stderr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	input := io.Reader(os.Stdin)
	if opts.Input != "" {
		file, err := os.Open(opts.Input)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer file.Close()
		input = file
	}

	urls, err := load.LoadSource(input)
	if err != nil {
		return err
	}

	if len(urls) == 0 {
		return errors.New("no URLs to probe")
	}

	log.Info("starting scan", "urls", len(urls), "workers", opts.Workers)

	s := scanner.New(opts.Rate, 10)

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			worker.Worker(ctx, log, s, jobs, opts)
		}()
	}

	go func() {
		for _, u := range urls {
			jobs <- u
		}
		close(jobs)
	}()

	wg.Wait()
	return nil
}
