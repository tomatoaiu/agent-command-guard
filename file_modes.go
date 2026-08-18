package main

import "strings"

// chmod's own options. A symbolic mode can also begin with "-" ("chmod -w
// file" removes write access), so options have to be recognised by name
// rather than by the leading dash.
var chmodOptions = map[string]bool{
	"-H": true,
	"-L": true,
	"-N": true,
	"-P": true,
	"-R": true,
	"-c": true,
	"-f": true,
	"-h": true,
	"-v": true,
}

// chmod takes its mode as the first operand that is not an option, and every
// operand after that is a path. Matching the literal string "777" anywhere in
// the argument list therefore reads a file named "777" as a mode, and misses
// every symbolic form that grants the same access.
func chmodGrantsWorldWrite(args []string, known []bool) bool {
	endOptions := false
	for i, arg := range args {
		if !endOptions {
			if arg == "--" {
				endOptions = true
				continue
			}
			if chmodOptions[arg] || strings.HasPrefix(arg, "--") {
				continue
			}
		}
		// The first operand that is not an option is the mode; the rest
		// are paths.
		if i >= len(known) || !known[i] {
			return false
		}
		return modeGrantsWorldWrite(arg)
	}
	return false
}

func modeGrantsWorldWrite(mode string) bool {
	if octal, ok := octalModeBits(mode); ok {
		return octal&0o002 != 0
	}
	return symbolicModeGrantsWorldWrite(mode)
}

// Numeric modes are three or four octal digits; the fourth, when present, is
// the leading setuid/setgid/sticky digit.
func octalModeBits(mode string) (int, bool) {
	if len(mode) < 3 || len(mode) > 4 {
		return 0, false
	}
	bits := 0
	for _, digit := range mode {
		if digit < '0' || digit > '7' {
			return 0, false
		}
		bits = bits*8 + int(digit-'0')
	}
	return bits, true
}

// A symbolic mode is a comma-separated list of clauses, each naming who is
// affected ("u", "g", "o", "a", or nothing, which means all), an operator, and
// the permissions. Only "+" and "=" hand out access; "-" takes it away.
func symbolicModeGrantsWorldWrite(mode string) bool {
	if mode == "" {
		return false
	}
	for _, clause := range strings.Split(mode, ",") {
		who, operator, permissions, ok := splitSymbolicClause(clause)
		if !ok {
			return false
		}
		if operator == '-' {
			continue
		}
		if !strings.ContainsAny(who, "oa") {
			continue
		}
		if strings.ContainsRune(permissions, 'w') {
			return true
		}
	}
	return false
}

func splitSymbolicClause(clause string) (who string, operator byte, permissions string, ok bool) {
	index := strings.IndexAny(clause, "+-=")
	if index < 0 {
		return "", 0, "", false
	}
	who = clause[:index]
	for _, letter := range who {
		if letter != 'u' && letter != 'g' && letter != 'o' && letter != 'a' {
			return "", 0, "", false
		}
	}
	// An omitted "who" means every class, which includes others.
	if who == "" {
		who = "a"
	}
	permissions = clause[index+1:]
	for _, letter := range permissions {
		if !strings.ContainsRune("rwxXst", letter) {
			return "", 0, "", false
		}
	}
	return who, clause[index], permissions, true
}
