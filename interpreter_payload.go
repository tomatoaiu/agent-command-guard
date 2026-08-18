package main

import "strings"

// An interpreter invoked with inline code carries a program the guard cannot
// parse, so nothing inside it is judged: a redirection at a protected path is
// refused while the same write expressed as open(path, "w") is not. That gap
// held every path protection hostage to the agent choosing the plain form.
//
// The payload cannot be understood, but it can be read. A path naming a
// protected or credential location inside it is enough to refuse the
// invocation: there is no way to tell what the code does with that path, and
// the only reason to write it there is to reach it.
//
// This is a Block, which also puts it out of reach of [[suppress]]. Suppressing
// inline-interpreter-code is a reasonable thing to want — the review it raises
// fires on every one-liner — but it must not double as a way past every path
// protection in the policy.
func (a *analyzer) inspectInterpreterPayloads(command string, args []string, known []bool) {
	for _, payload := range inlineInterpreterPayloads(command, args, known) {
		if target, ok := a.payloadNamesProtectedPath(payload); ok {
			a.add(Block, "protected-interpreter-payload", command, target)
		}
	}
}

func (a *analyzer) payloadNamesProtectedPath(payload string) (string, bool) {
	for _, token := range payloadPathTokens(payload) {
		expanded := strings.ReplaceAll(token, "${HOME}", a.home)
		expanded = strings.ReplaceAll(expanded, "$HOME", a.home)
		if a.protectedPath(expanded) || a.sensitiveReadPath(expanded) {
			return a.normalizePath(expanded), true
		}
	}
	return "", false
}

// Splits the payload on the characters that surround a path in source code of
// any language — quotes, brackets, operators, separators — and keeps the pieces
// that could name one. A token without a separator cannot be a path worth
// checking, and one carrying a scheme is a URL rather than a file.
func payloadPathTokens(payload string) []string {
	fields := strings.FieldsFunc(payload, func(r rune) bool {
		switch r {
		case '"', '\'', '`', ' ', '\t', '\n', '\r',
			'(', ')', '[', ']', '{', '}',
			',', ';', '+', '=', '<', '>', '|', '&', '!', '?', '*', ':':
			return true
		}
		return false
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		if !strings.Contains(field, "/") || strings.Contains(field, "//") {
			continue
		}
		tokens = append(tokens, field)
	}
	return tokens
}

// inlineInterpreterPayloads returns the inline programs passed to an
// interpreter. Only a payload the analyzer resolved is returned; one built at
// runtime carries no text to read.
func inlineInterpreterPayloads(command string, args []string, known []bool) []string {
	payloads := []string(nil)
	appendNext := func(index int) {
		next := index + 1
		if next < len(args) && next < len(known) && known[next] {
			payloads = append(payloads, args[next])
		}
	}
	if command == "deno" {
		for i, arg := range args {
			if arg == "eval" {
				appendNext(i)
			}
		}
		return payloads
	}
	flags := inlineInterpreterEvalFlags(command)
	if len(flags) == 0 {
		return nil
	}
	for i, arg := range args {
		for _, flag := range flags {
			if arg == flag {
				appendNext(i)
				break
			}
		}
	}
	return payloads
}
