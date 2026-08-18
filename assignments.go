package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// literalAssignments collects the variables in one parsed input whose value is
// fully determined by the source text, so that a later expansion of them can be
// resolved instead of being treated as dynamic.
//
// Resolving these matters in both directions. `R=/repo; git -C $R push origin
// main` is a protected push that would otherwise only be reviewed because the
// repository could not be identified, and `R=/repo; git -C $R add -A` is an
// ordinary command that would otherwise be reviewed for the same reason.
//
// A name is dropped when anything makes its value uncertain: a non-literal
// right-hand side, an append or indexed assignment, or two assignments in the
// same input that disagree. Dropping a name restores the previous behaviour for
// it, so an unresolved name is still reported as dynamic.
func literalAssignments(file *syntax.File) map[string]string {
	values := make(map[string]string)
	ambiguous := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Name == nil {
			return true
		}
		name := assign.Name.Value
		if assign.Append || assign.Index != nil || assign.Array != nil || assign.Naked {
			ambiguous[name] = true
			return true
		}
		value, ok := literalWordValue(assign.Value)
		if !ok {
			ambiguous[name] = true
			return true
		}
		if previous, seen := values[name]; seen && previous != value {
			ambiguous[name] = true
			return true
		}
		values[name] = value
		return true
	})
	for name := range ambiguous {
		delete(values, name)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// literalWordValue returns the text of a word that carries no expansion. A glob
// character is rejected because the shell decides its value from the filesystem
// rather than from the source.
func literalWordValue(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var builder strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return "", false
			}
			builder.WriteString(part.Value)
		case *syntax.SglQuoted:
			builder.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, nested := range part.Parts {
				literal, ok := nested.(*syntax.Lit)
				if !ok {
					return "", false
				}
				builder.WriteString(literal.Value)
			}
		default:
			return "", false
		}
	}
	return builder.String(), true
}

// assignedValue resolves a plain expansion such as $NAME or ${NAME}. Any form
// that transforms the value — a length, an index, a slice, a replacement, or a
// default — is refused, because the result no longer follows from the recorded
// assignment alone.
func assignedValue(expansion *syntax.ParamExp, assignments map[string]string) (string, bool) {
	if len(assignments) == 0 || expansion == nil || expansion.Param == nil {
		return "", false
	}
	if expansion.Excl || expansion.Length || expansion.Width ||
		expansion.Index != nil || expansion.Slice != nil ||
		expansion.Repl != nil || expansion.Exp != nil || expansion.Names != 0 {
		return "", false
	}
	value, ok := assignments[expansion.Param.Value]
	return value, ok
}
