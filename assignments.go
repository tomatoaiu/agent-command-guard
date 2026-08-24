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
// A value may be built from names assigned earlier in the same input, which is
// how scripts usually name a directory once and derive paths from it:
//
//	SCRATCH=/tmp/work; TMP="$SCRATCH/merged"; rm -rf "$TMP"
//
// Assignments are therefore read in source order, and each one may use the
// names resolved before it. Only earlier names count: a value that reads a name
// assigned further down would be empty at the moment it runs, so resolving it
// from the later assignment would describe a command that never happens.
//
// A name is dropped when anything makes its value uncertain: a right-hand side
// that cannot be resolved from the source and the names before it, an append or
// indexed assignment, or two assignments in the same input that disagree.
// Dropping a name restores the previous behaviour for it, so an unresolved name
// is still reported as dynamic.
func literalAssignments(file *syntax.File, home string) map[string]string {
	values := make(map[string]string)
	// evalWord resolves $HOME on its own, so seeding it here is what makes a
	// value derived from it resolve the same way. Without this, "rm -rf $HOME"
	// is blocked while "H=$HOME; rm -rf $H" is not.
	if home != "" {
		values["HOME"] = home
	}
	ambiguous := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Name == nil {
			return true
		}
		name := assign.Name.Value
		// A name that has become uncertain is withdrawn immediately rather
		// than at the end, so that a later value cannot be built from it. The
		// walk follows source order, not control flow, so two assignments in
		// different branches look like a straight-line reassignment; keeping
		// the first value available would describe one branch as if it were
		// the only one.
		if assign.Append || assign.Index != nil || assign.Array != nil || assign.Naked {
			ambiguous[name] = true
			delete(values, name)
			return true
		}
		value, ok := resolvedWordValue(assign.Value, values)
		if !ok {
			ambiguous[name] = true
			delete(values, name)
			return true
		}
		if ambiguous[name] {
			return true
		}
		if previous, seen := values[name]; seen && previous != value {
			ambiguous[name] = true
			delete(values, name)
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

// assignedNames reports every name the input assigns to, whether or not the
// value could be resolved. A for loop only binds its variable when the name is
// absent here, because an assignment anywhere in the input decides what the
// loop body reads instead of the item being iterated.
func assignedNames(file *syntax.File) map[string]bool {
	names := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		if assign, ok := node.(*syntax.Assign); ok && assign.Name != nil {
			names[assign.Name.Value] = true
		}
		return true
	})
	return names
}

// resolvedWordValue returns the text of a word that carries no expansion beyond
// the names already resolved. A glob character is rejected because the shell
// decides its value from the filesystem rather than from the source.
func resolvedWordValue(word *syntax.Word, values map[string]string) (string, bool) {
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
				switch nested := nested.(type) {
				case *syntax.Lit:
					builder.WriteString(nested.Value)
				case *syntax.ParamExp:
					value, ok := assignedValue(nested, values)
					if !ok {
						return "", false
					}
					builder.WriteString(value)
				default:
					return "", false
				}
			}
		case *syntax.ParamExp:
			value, ok := assignedValue(part, values)
			if !ok {
				return "", false
			}
			builder.WriteString(value)
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
