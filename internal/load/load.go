package load

import (
	"io"
	"bufio"
	"strings"
	"fmt"
)

const maxLine = 1 << 20

func LoadSource(r io.Reader) ([]string, error) {
	var read []string

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		} 
		read = append(read, line)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	return read, nil
}
