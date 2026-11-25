package contract

import (
	"context"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// confirm re-runs each security and robustness finding on new test records.
// A finding that does not reproduce stays in the report with its tally.
func (f *fuzzer) confirm(ctx context.Context) {
	if f.options.Confirmations == 0 {
		return
	}
	for _, finding := range aggregate(f.s.doc, f.report.Cases) {
		switch {
		case finding.Category == CategoryContract, finding.Category == CategoryHTTP, finding.Kind == FindingVersionDisclosure:
			// These depend on the contract and the server, not on test data.
			continue
		}
		chain := f.closure(finding.Cases[0])
		for round := range f.options.Confirmations {
			if f.halted(ctx) || len(chain) == 0 {
				return
			}
			reproduced, conclusive := f.rerun(ctx, chain, finding.Kind, round+1)
			tally := f.confirmed[finding.Kind+" "+finding.Operation()]
			if conclusive {
				tally[1]++
			}
			if reproduced {
				tally[0]++
			}
			f.confirmed[finding.Kind+" "+finding.Operation()] = tally
		}
	}
}

// closure returns the target case and every earlier case it depends on,
// through needs or through a variable, in execution order.
func (f *fuzzer) closure(target string) []Case {
	writer := make(map[string]int)
	index := make(map[string]int, len(f.suite.Cases))
	depends := make([][]int, len(f.suite.Cases))
	last := -1
	for i, c := range f.suite.Cases {
		index[c.Name] = i
		used := make(map[string]bool)
		for _, name := range c.references() {
			used[name] = true
		}
		for _, expression := range c.Set {
			references(expression, used)
		}
		for name := range used {
			// A case reads the value an earlier case wrote, not its own Set.
			if at, ok := writer[name]; ok {
				if _, own := c.Set[name]; !own {
					depends[i] = append(depends[i], at)
				}
			}
		}
		for _, name := range c.Needs {
			if at, ok := index[name]; ok {
				depends[i] = append(depends[i], at)
			}
		}
		for name := range c.Set {
			writer[name] = i
		}
		for name := range c.Capture {
			writer[name] = i
		}
		if c.Name == target {
			last = i
			break
		}
	}
	if last < 0 {
		return nil
	}
	include := map[int]bool{last: true}
	pending := []int{last}
	for len(pending) != 0 {
		at := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, dependency := range depends[at] {
			if !include[dependency] {
				include[dependency] = true
				pending = append(pending, dependency)
			}
		}
	}
	chain := make([]Case, 0, len(include))
	for _, at := range slices.Sorted(maps.Keys(include)) {
		chain = append(chain, f.suite.Cases[at])
	}
	return chain
}

// rerun executes a copy of the chain with new names and variables. It
// reports whether the last case raised the finding again and whether it ran.
func (f *fuzzer) rerun(ctx context.Context, chain []Case, kind string, round int) (reproduced, conclusive bool) {
	f.sequence++
	suffix := "r" + strconv.Itoa(round) + "x" + strconv.Itoa(f.sequence)
	renamed := make(map[string]string)
	for _, c := range chain {
		for name := range c.Set {
			renamed[name] = name + suffix
		}
		for name := range c.Capture {
			renamed[name] = name + suffix
		}
	}
	rewrite := func(text string) string {
		for old, replacement := range renamed {
			text = strings.ReplaceAll(text, "${"+old+"}", "${"+replacement+"}")
			text = strings.ReplaceAll(text, url.QueryEscape("${"+old+"}"), url.QueryEscape("${"+replacement+"}"))
		}
		return text
	}
	rename := func(values map[string]string, keys bool) map[string]string {
		if values == nil {
			return nil
		}
		out := make(map[string]string, len(values))
		for name, value := range values {
			if keys {
				name = renamed[name]
			}
			out[name] = rewrite(value)
		}
		return out
	}
	label := func(name string) string { return name + " · confirm " + suffix }
	var result Result
	for _, original := range chain {
		c := original
		c.Name = label(original.Name)
		c.Needs = make([]string, len(original.Needs))
		for i, name := range original.Needs {
			c.Needs[i] = label(name)
		}
		c.Query, c.Form, c.JSONBody, c.Body = rewrite(c.Query), rewrite(c.Form), rewrite(c.JSONBody), rewrite(c.Body)
		c.PathParams, c.Headers = rename(c.PathParams, false), rename(c.Headers, false)
		c.Set = rename(c.Set, true)
		if original.Capture != nil {
			c.Capture = make(map[string]string, len(original.Capture))
			for name, pointer := range original.Capture {
				c.Capture[renamed[name]] = pointer
			}
		}
		if original.Multipart != nil {
			c.Multipart = make(map[string]Part, len(original.Multipart))
			for name, part := range original.Multipart {
				part.Value = rewrite(part.Value)
				c.Multipart[name] = part
			}
		}
		result, _ = f.run(ctx, nil, c, false)
		if f.lost[original.Name] && accepted(result) {
			f.leftover++
		}
		// A copied creation made a new record that needs removing too.
		for _, record := range f.records {
			if record.source != original.Name || !record.recorded || !accepted(result) {
				continue
			}
			copied := &testRecord{resource: record.resource, variable: renamed[record.variable], source: c.Name,
				alive: true, owned: true, path: rename(record.path, false)}
			f.records = append(f.records, copied)
			break
		}
	}
	if result.Skipped != "" || result.Status == 0 {
		return false, false
	}
	for _, signal := range slices.Concat(result.Findings, result.Problems) {
		raised, _, _ := strings.Cut(signal, " ")
		// A made-up credential that works confirms missing enforcement as well.
		if raised == kind || (kind == FindingAuthNotEnforced && raised == FindingInvalidCredential) {
			return true, true
		}
	}
	return false, true
}
