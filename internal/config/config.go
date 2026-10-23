package config

import "fmt"

type Reflected struct {
	URL		string
	Params	[]string
}

type ResultChars struct {
	URL			string
	Param		string
	Chars		[]string
}

type ResultPayloads struct {
	URL			string
	Param		string
	Payloads	[]string
}

type Options struct {
	Input		string
	Workers 	int
	Rate		float64
	Payload		string
	FuzzPayload	bool
}

func (o Options) Validate() error {
	if o.Workers < 1 {
		return fmt.Errorf("workers must be at least 1, got %d", o.Workers)
	}

	if o.Rate < 1 {
		return fmt.Errorf("rate limit must be at least 1, got %f", o.Rate)
	}

	if o.FuzzPayload && o.Payload == "" {
		return fmt.Errorf("payloads are required when 'fuzz payload' is enabled")
	}

	return nil
}
