package main

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const maxPOSIXCWDs = 32

type posixCallContext struct {
	cwd                              string
	cwdKnown                         bool
	protectedGitExceptionEligibility protectedGitExceptionEligibility
	protectedCommitArgumentsSafe     bool
	protectedCommitArgumentsChecked  bool
}

type posixRedirectContext struct {
	cwd      string
	cwdKnown bool
}

type posixSourceContexts struct {
	calls     map[*syntax.CallExpr]posixCallContext
	redirects map[*syntax.Redirect]posixRedirectContext
}

type posixCWDSet struct {
	values  map[string]struct{}
	unknown bool
}

type posixCWDFlow struct {
	success posixCWDSet
	failure posixCWDSet
}

type posixContextBuilder struct {
	depth          int
	home           string
	assignments    map[string]string
	shellFunctions map[string]bool
	contexts       posixSourceContexts
}

func buildPOSIXContexts(file *syntax.File, depth int, cwd string, cwdKnown bool, home string, assignments map[string]string) posixSourceContexts {
	builder := posixContextBuilder{
		depth:       depth,
		home:        home,
		assignments: assignments,
		contexts: posixSourceContexts{
			calls:     make(map[*syntax.CallExpr]posixCallContext),
			redirects: make(map[*syntax.Redirect]posixRedirectContext),
		},
	}
	initial := unknownPOSIXCWDSet()
	if cwdKnown {
		initial = knownPOSIXCWDSet(cwd)
	}
	builder.shellFunctions = posixFunctionNames(file)
	builder.statements(file.Stmts, initial, false)
	return builder.contexts
}

func posixFunctionNames(file *syntax.File) map[string]bool {
	functions := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, ok := node.(*syntax.FuncDecl); ok && declaration.Name != nil {
			functions[normalizeCommandName(declaration.Name.Value)] = true
		}
		return true
	})
	return functions
}

func knownPOSIXCWDSet(cwd string) posixCWDSet {
	return posixCWDSet{values: map[string]struct{}{filepath.Clean(cwd): {}}}
}

func unknownPOSIXCWDSet() posixCWDSet {
	return posixCWDSet{unknown: true}
}

func emptyPOSIXCWDSet() posixCWDSet {
	return posixCWDSet{}
}

func mergePOSIXCWDSets(sets ...posixCWDSet) posixCWDSet {
	merged := posixCWDSet{values: make(map[string]struct{})}
	for _, set := range sets {
		if set.unknown {
			merged.unknown = true
		}
		for value := range set.values {
			merged.values[value] = struct{}{}
			if len(merged.values) > maxPOSIXCWDs {
				return unknownPOSIXCWDSet()
			}
		}
	}
	return merged
}

func (s posixCWDSet) single() (string, bool) {
	if s.unknown || len(s.values) != 1 {
		return "", false
	}
	for value := range s.values {
		return value, true
	}
	return "", false
}

func (f posixCWDFlow) all() posixCWDSet {
	return mergePOSIXCWDSets(f.success, f.failure)
}

func uncertainPOSIXCWDFlow(cwd posixCWDSet) posixCWDFlow {
	return posixCWDFlow{success: cwd, failure: cwd}
}

func (b *posixContextBuilder) statements(statements []*syntax.Stmt, in posixCWDSet, indirect bool) posixCWDFlow {
	if len(statements) == 0 {
		return posixCWDFlow{success: in}
	}
	flow := uncertainPOSIXCWDFlow(in)
	for _, statement := range statements {
		flow = b.statement(statement, flow.all(), indirect)
	}
	return flow
}

func (b *posixContextBuilder) statement(statement *syntax.Stmt, in posixCWDSet, indirect bool) posixCWDFlow {
	if statement == nil {
		return uncertainPOSIXCWDFlow(in)
	}
	for _, redirection := range statement.Redirs {
		cwd, cwdKnown := in.single()
		b.contexts.redirects[redirection] = posixRedirectContext{cwd: cwd, cwdKnown: cwdKnown}
		b.mapNestedShells(redirection, in)
	}
	invocationIndirect := indirect || statement.Background || statement.Coprocess
	flow := b.command(statement.Cmd, in, invocationIndirect)
	if statement.Background || statement.Coprocess {
		flow = uncertainPOSIXCWDFlow(in)
	}
	if statement.Negated {
		flow.success, flow.failure = flow.failure, flow.success
	}
	return flow
}

func (b *posixContextBuilder) command(command syntax.Command, in posixCWDSet, indirect bool) posixCWDFlow {
	if command == nil {
		return uncertainPOSIXCWDFlow(in)
	}
	switch command := command.(type) {
	case *syntax.CallExpr:
		return b.call(command, in, indirect)
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.AndStmt:
			left := b.statement(command.X, in, indirect)
			right := b.statement(command.Y, left.success, indirect)
			return posixCWDFlow{success: right.success, failure: mergePOSIXCWDSets(left.failure, right.failure)}
		case syntax.OrStmt:
			left := b.statement(command.X, in, indirect)
			right := b.statement(command.Y, left.failure, indirect)
			return posixCWDFlow{success: mergePOSIXCWDSets(left.success, right.success), failure: right.failure}
		case syntax.Pipe, syntax.PipeAll:
			b.statement(command.X, in, indirect)
			b.statement(command.Y, in, indirect)
			return uncertainPOSIXCWDFlow(in)
		default:
			return b.mapConservative(command, in, true)
		}
	case *syntax.Block:
		return b.statements(command.Stmts, in, indirect)
	case *syntax.Subshell:
		b.statements(command.Stmts, in, true)
		return uncertainPOSIXCWDFlow(in)
	case *syntax.TimeClause:
		if command.Stmt != nil {
			return b.statement(command.Stmt, in, true)
		}
		return uncertainPOSIXCWDFlow(in)
	case *syntax.CoprocClause:
		if command.Stmt != nil {
			b.statement(command.Stmt, in, true)
		}
		return uncertainPOSIXCWDFlow(in)
	case *syntax.FuncDecl:
		if command.Body != nil {
			// A function runs at its call site's working directory, not where it
			// was declared. Calls are intentionally not interpreted here, so the
			// body must remain unknown rather than inheriting a misleading path.
			b.statement(command.Body, unknownPOSIXCWDSet(), true)
		}
		return uncertainPOSIXCWDFlow(in)
	default:
		return b.mapConservative(command, in, true)
	}
}

func (b *posixContextBuilder) call(call *syntax.CallExpr, in posixCWDSet, indirect bool) posixCWDFlow {
	b.mapNestedShells(call, in)
	cwd, cwdKnown := in.single()
	commandName, commandKnown := directPOSIXCommandName(call, b.home, b.assignments)
	functionCall := commandKnown && b.shellFunctions[commandName]
	eligibility := posixProtectedGitExceptionEligibility(call, b.depth, indirect || functionCall, b.home, b.assignments)
	commitSafe, commitChecked := safeProtectedPOSIXCommitCall(call, b.home, b.assignments)
	b.contexts.calls[call] = posixCallContext{
		cwd:                              cwd,
		cwdKnown:                         cwdKnown,
		protectedGitExceptionEligibility: eligibility,
		protectedCommitArgumentsSafe:     commitSafe,
		protectedCommitArgumentsChecked:  commitChecked,
	}

	if functionCall || commandKnown && (commandName == "source" || commandName == "." || commandName == "eval") {
		return uncertainPOSIXCWDFlow(unknownPOSIXCWDSet())
	}
	if directPOSIXExit(call, b.home, b.assignments) {
		return posixCWDFlow{success: emptyPOSIXCWDSet(), failure: emptyPOSIXCWDSet()}
	}
	directory, isCD := directPOSIXCD(call, b.home, b.assignments)
	if !isCD {
		return uncertainPOSIXCWDFlow(in)
	}
	return posixCWDFlow{success: resolvePOSIXCD(directory, in, b.home), failure: in}
}

func (b *posixContextBuilder) mapNestedShells(node syntax.Node, in posixCWDSet) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CmdSubst:
			b.statements(node.Stmts, in, true)
			return false
		case *syntax.ProcSubst:
			b.statements(node.Stmts, in, true)
			return false
		}
		return true
	})
}

func (b *posixContextBuilder) mapConservative(node syntax.Node, in posixCWDSet, indirect bool) posixCWDFlow {
	if node == nil {
		return uncertainPOSIXCWDFlow(in)
	}
	state := in
	if posixTreeMayChangeCWD(node, b.home, b.assignments, b.shellFunctions) {
		state = unknownPOSIXCWDSet()
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		cwd, cwdKnown := state.single()
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Body != nil {
				b.statement(node.Body, unknownPOSIXCWDSet(), true)
			}
			return false
		case *syntax.Subshell:
			b.statements(node.Stmts, state, true)
			return false
		case *syntax.CmdSubst:
			b.statements(node.Stmts, state, true)
			return false
		case *syntax.ProcSubst:
			b.statements(node.Stmts, state, true)
			return false
		case *syntax.TimeClause:
			if node.Stmt != nil {
				b.statement(node.Stmt, state, true)
			}
			return false
		case *syntax.CoprocClause:
			if node.Stmt != nil {
				b.statement(node.Stmt, state, true)
			}
			return false
		case *syntax.CallExpr:
			commandName, commandKnown := directPOSIXCommandName(node, b.home, b.assignments)
			functionCall := commandKnown && b.shellFunctions[commandName]
			commitSafe, commitChecked := safeProtectedPOSIXCommitCall(node, b.home, b.assignments)
			b.contexts.calls[node] = posixCallContext{
				cwd:                              cwd,
				cwdKnown:                         cwdKnown,
				protectedGitExceptionEligibility: posixProtectedGitExceptionEligibility(node, b.depth, indirect || functionCall, b.home, b.assignments),
				protectedCommitArgumentsSafe:     commitSafe,
				protectedCommitArgumentsChecked:  commitChecked,
			}
		case *syntax.Redirect:
			b.contexts.redirects[node] = posixRedirectContext{cwd: cwd, cwdKnown: cwdKnown}
		}
		return true
	})
	return uncertainPOSIXCWDFlow(state)
}

func posixTreeMayChangeCWD(node syntax.Node, home string, assignments map[string]string, shellFunctions map[string]bool) bool {
	if node == nil {
		return false
	}
	found := false
	syntax.Walk(node, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		command, known := directPOSIXCommandName(call, home, assignments)
		if _, isCD := directPOSIXCD(call, home, assignments); isCD || known && (shellFunctions[command] || command == "source" || command == "." || command == "eval") {
			found = true
			return false
		}
		return true
	})
	return found
}

func directPOSIXCommandName(call *syntax.CallExpr, home string, assignments map[string]string) (string, bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false
	}
	command := evalWord(call.Args[0], home, assignments)
	return normalizeCommandName(command.Value), command.Known
}

func directPOSIXExit(call *syntax.CallExpr, home string, assignments map[string]string) bool {
	if call == nil || len(call.Assigns) > 0 {
		return false
	}
	command, known := directPOSIXCommandName(call, home, assignments)
	return known && command == "exit"
}

func directPOSIXCD(call *syntax.CallExpr, home string, assignments map[string]string) (wordValue, bool) {
	if call == nil || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return wordValue{}, false
	}
	command := evalWord(call.Args[0], home, assignments)
	if !command.Known {
		return wordValue{}, false
	}
	argumentStart := 1
	name := normalizeCommandName(command.Value)
	if name == "builtin" || name == "command" {
		for argumentStart < len(call.Args) {
			wrapped := evalWord(call.Args[argumentStart], home, assignments)
			if !wrapped.Known {
				return wordValue{Known: false}, true
			}
			if wrapped.Value == "--" {
				argumentStart++
				continue
			}
			name = normalizeCommandName(wrapped.Value)
			argumentStart++
			break
		}
	}
	if name == "pushd" || name == "popd" {
		return wordValue{Known: false}, true
	}
	if name != "cd" && name != "chdir" {
		return wordValue{}, false
	}
	path := wordValue{Value: home, Known: home != ""}
	pathSeen := false
	endOptions := false
	for _, argument := range call.Args[argumentStart:] {
		value := evalWord(argument, home, assignments)
		if !value.Known {
			return wordValue{Known: false}, true
		}
		if !endOptions && value.Value == "--" {
			endOptions = true
			continue
		}
		if !endOptions && (value.Value == "-L" || value.Value == "-P" || value.Value == "-e" || value.Value == "-@") {
			continue
		}
		if pathSeen {
			return wordValue{Known: false}, true
		}
		path, pathSeen = value, true
	}
	return path, true
}

func resolvePOSIXCD(directory wordValue, in posixCWDSet, home string) posixCWDSet {
	if !directory.Known || directory.Value == "" || directory.Value == "-" || in.unknown {
		return unknownPOSIXCWDSet()
	}
	if !filepath.IsAbs(directory.Value) && directory.Value != "." && directory.Value != ".." &&
		!strings.HasPrefix(directory.Value, "./") && !strings.HasPrefix(directory.Value, "../") {
		// CDPATH may redirect a bare relative directory to a location outside
		// the current working directory.
		return unknownPOSIXCWDSet()
	}
	resolved := posixCWDSet{values: make(map[string]struct{})}
	for cwd := range in.values {
		resolved.values[resolveGitCWD(cwd, directory.Value)] = struct{}{}
		if len(resolved.values) > maxPOSIXCWDs {
			return unknownPOSIXCWDSet()
		}
	}
	return resolved
}

func posixProtectedGitExceptionEligibility(call *syntax.CallExpr, depth int, indirect bool, home string, assignments map[string]string) protectedGitExceptionEligibility {
	if depth != 0 || indirect || call == nil || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	command, static := staticPOSIXWord(call.Args[0], home, assignments)
	if !static {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	if normalizeCommandName(command) != "git" {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	return protectedGitExceptionEligibility{Eligible: true, Reason: protectedGitExceptionEligible}
}

func staticPOSIXWord(word *syntax.Word, home string, assignments map[string]string) (string, bool) {
	static := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
			static = false
			return false
		}
		return true
	})
	value := evalWord(word, home, assignments)
	return value.Value, static && value.Known
}

func safeProtectedPOSIXCommitCall(call *syntax.CallExpr, home string, assignments map[string]string) (bool, bool) {
	if call == nil || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return false, false
	}
	command, static := staticPOSIXWord(call.Args[0], home, assignments)
	if !static || normalizeCommandName(command) != "git" {
		return false, false
	}

	index := 1
	for index < len(call.Args) {
		value := evalWord(call.Args[index], home, assignments)
		if !value.Known {
			return false, false
		}
		switch {
		case value.Value == "-c":
			if index+1 >= len(call.Args) {
				return false, true
			}
			override := evalWord(call.Args[index+1], home, assignments)
			if !override.Known || !safeGitConfigOverrideForException(override.Value) {
				return false, true
			}
			index += 2
			continue
		case value.Value == "-C":
			if index+1 >= len(call.Args) || !evalWord(call.Args[index+1], home, assignments).Known {
				return false, false
			}
			index += 2
			continue
		case strings.HasPrefix(value.Value, "-C") && len(value.Value) > 2:
			index++
			continue
		case strings.HasPrefix(value.Value, "-"):
			return false, false
		}
		break
	}
	if index >= len(call.Args) {
		return false, false
	}
	subcommand := evalWord(call.Args[index], home, assignments)
	if !subcommand.Known || subcommand.Value != "commit" {
		return false, false
	}
	index++

	expectsMessage := false
	for ; index < len(call.Args); index++ {
		word := call.Args[index]
		value := evalWord(word, home, assignments)
		if posixWordHasUnquotedGlob(word) {
			return false, true
		}
		if !value.Known {
			if !expectsMessage || !posixWordExpandsToSingleArgument(word) {
				return false, true
			}
			expectsMessage = false
			continue
		}
		if expectsMessage {
			expectsMessage = false
			continue
		}
		if protectedCommitArgumentDisablesHooks(value.Value) {
			return false, true
		}
		if value.Value == "-m" || value.Value == "--message" {
			expectsMessage = true
		}
	}
	return !expectsMessage, true
}

func posixWordHasUnquotedGlob(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return true
			}
		case *syntax.ExtGlob, *syntax.BraceExp:
			return true
		}
	}
	return false
}

func posixWordExpandsToSingleArgument(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			continue
		case *syntax.DblQuoted:
			single := true
			syntax.Walk(part, func(node syntax.Node) bool {
				parameter, ok := node.(*syntax.ParamExp)
				if ok && parameter.Param != nil && parameter.Param.Value == "@" {
					single = false
					return false
				}
				return true
			})
			if !single {
				return false
			}
		default:
			return false
		}
	}
	return true
}
