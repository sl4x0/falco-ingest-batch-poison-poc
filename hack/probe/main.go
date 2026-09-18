package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func unq(raw json.RawMessage) (string, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	return strconv.Unquote(string(b))
}

func main() {
	// 1. absent key
	var absent json.RawMessage
	b, _ := json.Marshal(absent)
	s, err := strconv.Unquote(string(b))
	fmt.Printf("absent: marshaled=%q unquote=%q err=%v\n", string(b), s, err)

	// 2. raw string
	r := json.RawMessage(`"shoot--p--c-123e4567-e89b-12d3-a456-426614174000-l"`)
	b2, _ := json.Marshal(r)
	s2, err2 := strconv.Unquote(string(b2))
	fmt.Printf("string: marshaled=%q unquote=%q err=%v\n", string(b2), s2, err2)

	// 3. single-quoted go-literal raw json
	r3 := json.RawMessage(`'abc'`)
	b3, err3 := json.Marshal(r3)
	fmt.Printf("singlequote: marshaled=%q marshalErr=%v\n", string(b3), err3)

	// 4. whitespace padded
	r4 := json.RawMessage("  \"victim\"  ")
	b4, err4 := json.Marshal(r4)
	s4, errU4 := strconv.Unquote(string(b4))
	fmt.Printf("padded: marshaled=%q err=%v unquote=%q err=%v\n", string(b4), err4, s4, errU4)

	// 5. regex ambiguity probe
	re := `^shoot--([\w-]+)--([\w-]+)-([a-fA-F\d]{8}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{12})-([\w-]+)$`
	rx := regexp.MustCompile(re)
	uuid := "123e4567-e89b-12d3-a456-426614174000"
	cands := []string{
		"shoot--project--cluster-" + uuid + "-landscape",
		"shoot--proj-ect--cluster-" + uuid + "-landscape",
		"shoot--project--clu-ster-" + uuid + "-landscape",
		"shoot--project--cluster-" + uuid + "-land-scape",
		"shoot--project---cluster-" + uuid + "-landscape",
		"shoot--project--cluster--" + uuid + "-landscape",
		"shoot--project--cluster-" + uuid + "--landscape",
		"shoot---project--cluster-" + uuid + "-landscape",
		"shoot--project--cluster-" + uuid + "-landscape-extra",
		"shoot--a--b--c--d--e--" + uuid + "-l",
	}
	for _, c := range cands {
		m := rx.FindStringSubmatch(c)
		fmt.Printf("regex %-70s -> %q\n", c, m)
	}

	// 6. panic probe on malformed token (segment count)
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("PANIC on parts[2]:", r)
			}
		}()
		tok := "onlyonesegment"
		parts := strings.Split(tok, ".")
		_ = parts[2]
	}()
}
