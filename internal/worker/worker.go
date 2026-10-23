package worker

import (
	"io"
	"os"
	"fmt"
	"context"
	"log/slog"
	"strings"
	
	"golang.org/x/term"

	"qxss/internal/config"
	"qxss/internal/load"
	"qxss/internal/scanner"
)

const colorReset = "\033[0m"
const colorYellow = "\033[33m"
// // const colorRed = "\033[31m"
const colorGreen = "\033[32m"
// // const black = "\033[30m"
// // const red = "\033[31m"
// // const blue = "\033[34m"
// // const magenta = "\033[35m"
// // const cyan = "\033[36m"

var useColor = term.IsTerminal(int(os.Stdout.Fd()))

func colorize(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + colorReset
}

func Worker(ctx context.Context, log *slog.Logger, s *scanner.Scanner, jobs <-chan string, o config.Options) {
	if o.FuzzPayload {
		payload := io.Reader(os.Stdin)
		if o.Payload != "" {
			file, err := os.Open(o.Payload)
			if err != nil {
				log.Error("open file failed", "file", o.Payload, "err", err)
			}
			defer file.Close()
			payload = file
		}

		payloads, err := load.LoadSource(payload)
		if err != nil {
			log.Error("load payloads failed", "err", err)
		}

		if len(payloads) == 0 {
			log.Error("no payloads supplied")
		}

		for u := range jobs {
			reflected, err := s.Params(ctx, u)
			if err != nil {
				log.Error("probe failed", "url", u, "err", err)
				continue
			}
	
			for _, param := range reflected.Params {
				result, err := s.FuzzPayloads(ctx, reflected.URL, param, payloads)
				if err != nil {
					log.Error("fuzz failed", "url", u, "param", param, "err", err)
					continue
				}
				fmt.Fprintf(os.Stdout, "%s\n", reflected.URL)
				fmt.Fprintf(os.Stdout, " └ ?%s=\n", colorize(colorYellow, param))
				fmt.Fprintf(os.Stdout, " └ %v\n\n", colorize(colorGreen, strings.Join(result.Payloads, "\n └ ")))
			}
		}
	} else {
		for u := range jobs {
			reflected, err := s.Params(ctx, u)
			if err != nil {
				log.Error("probe failed", "url", u, "err", err)
				continue
			}
	
			for _, param := range reflected.Params {
				result, err := s.FuzzChars(ctx, reflected.URL, param)
				if err != nil {
					log.Error("fuzz failed", "url", u, "param", param, "err", err)
					continue
				}
				fmt.Fprintf(os.Stdout, "%s\n", reflected.URL)
				fmt.Fprintf(os.Stdout, " └ ?%s=\n", colorize(colorYellow, param))
				fmt.Fprintf(os.Stdout, " └ %v\n\n", colorize(colorGreen, strings.Join(result.Chars, " ")))
			}
		}
	}
}
