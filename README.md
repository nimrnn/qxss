# qxss

`qxss` is a small, fast, concurrent reflected-XSS recon tool written in Go.

It reads a list of URLs (from a file or stdin), then for every URL:

1. **Finds reflected parameters** — for each query-string parameter it injects a random
   hex canary and checks whether the canary appears in the response body.
2. **Probes what survives reflection** (default mode) — for each reflected parameter it
   sends a canary followed by a special character (`<`, `>`, `"`, `'`, `{`, `}`, `(`, `)`,
   `[`, `]`, `\`, `/`, `;`, `` ` ``, `-`) and reports which characters are reflected back
   unencoded, giving you a quick idea of what a working payload could be built from.
3. **Fuzzes payloads** (`-fuzz-payload`) — for each reflected parameter it sends every
   payload from a wordlist (see [`payloads.txt`](./payloads.txt)) prefixed with a canary and
   reports the payloads that are reflected verbatim.

Requests are rate limited and executed concurrently, and the scan can be interrupted
with `Ctrl+C`.

## Usage

Build it first:

```sh
go build -o qxss ./cmd/quick-xss
```

Find reflected parameters and the characters that survive:

```sh
./qxss -input urls.txt -workers 8 -rate 10
```

Fuzz payloads from a wordlist:

```sh
./qxss -input urls.txt -payload payloads.txt -fuzz-payload -workers 8 -rate 10
```

URLs and payloads can also be piped in on stdin. Blank lines and lines starting with `#`
are ignored.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-input` | `""` (stdin) | File with one URL per line |
| `-workers` | `8` | Number of concurrent workers |
| `-rate` | `10` | Request rate limit (requests per second) |
| `-payload` | `""` (stdin) | File with one XSS payload per line |
| `-fuzz-payload` | `false` | Switch to payload fuzzing, skipping the character probes |

## Output

For each URL the tool prints the reflected parameters and, below each one, either the
list of allowed special characters or the list of payloads that were reflected back:

```
http://example.com/search?q=test
 └ ?q=
 └ < > " '
```

## Disclaimer

Only use this against systems you own or are explicitly authorized to test. Reflected
output does not by itself prove that a payload executes.

## TODO

- [ ] **CDP-based confirmation.** Hook into a real browser over the Chrome DevTools
      Protocol to reliably determine whether a payload actually triggers (e.g. by
      registering `alert`/`dialog` handlers or injecting a JS hook and waiting for
      execution), instead of relying on plaintext reflection in the response body.
- [ ] **LLM payload crafting.** Feed the reflected character set (output of the character
      probes) to an LLM so it can generate context-appropriate payloads that only use the
      characters that survive filtering/encoding. For example, if only `<` and `>` are
      reflected, the LLM should craft a working payload that uses those characters only,
      somehow.
- [ ] **Reflection context.** On top of identifying which parameters reflect their values
      in response body, also determine where the reflection occurs - in between tags `<p></p>`
      , HTML attributes `<a href=""></a>`, within JavaScript `<script></script>`
