package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type powerShellDocument struct {
	ParseErrors         []string                `json:"parse_errors"`
	Commands            []powerShellCommand     `json:"commands"`
	Pipelines           []powerShellPipeline    `json:"pipelines"`
	Redirections        []powerShellRedirection `json:"redirections"`
	SingleDirectCommand bool                    `json:"single_direct_command"`
	StatementCount      int                     `json:"statement_count"`
	HasAssignment       bool                    `json:"has_assignment"`
	HasChain            bool                    `json:"has_chain"`
}

type powerShellCommand struct {
	Name               string              `json:"name"`
	NameKnown          bool                `json:"name_known"`
	InvocationOperator string              `json:"invocation_operator"`
	Elements           []powerShellElement `json:"elements"`
}

type powerShellElement struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Text  string `json:"text"`
	Known bool   `json:"known"`
}

type powerShellPipeline struct {
	Commands []powerShellCommand `json:"commands"`
}

type powerShellRedirection struct {
	Target powerShellElement `json:"target"`
}

const powerShellParserScript = `$ErrorActionPreference = 'Stop'

function Convert-GuardValue {
    param([System.Management.Automation.Language.Ast] $Node)

    $known = $false
    $value = ''
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
        $known = $true
        $value = [string] $Node.Value
    }
    elseif ($Node -is [System.Management.Automation.Language.ConstantExpressionAst]) {
        $known = $true
        $value = [string] $Node.Value
    }
    elseif ($Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $Node.NestedExpressions.Count -eq 0) {
        $known = $true
        $value = [string] $Node.Value
    }

    [pscustomobject] [ordered] @{
        kind = 'argument'
        value = $value
        text = [string] $Node.Extent.Text
        known = $known
    }
}

function Convert-GuardCommand {
    param([System.Management.Automation.Language.CommandAst] $Command)

    $name = $Command.GetCommandName()
    $elements = @()
    for ($index = 1; $index -lt $Command.CommandElements.Count; $index++) {
        $element = $Command.CommandElements[$index]
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $elements += [pscustomobject] [ordered] @{
                kind = 'parameter'
                value = '-' + [string] $element.ParameterName
                text = [string] $element.Extent.Text
                known = $true
            }
            if ($null -ne $element.Argument) {
                $elements += Convert-GuardValue $element.Argument
            }
        }
        else {
            $elements += Convert-GuardValue $element
        }
    }

    [pscustomobject] [ordered] @{
        name = if ($null -eq $name) { '' } else { [string] $name }
        name_known = $null -ne $name
        invocation_operator = [string] $Command.InvocationOperator
        elements = @($elements)
    }
}

$encodedSource = [Console]::In.ReadToEnd().Trim()
$source = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedSource))
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref] $tokens, [ref] $parseErrors)

$commands = @(
    $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { Convert-GuardCommand $_ }
)

$pipelines = @(
    $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.PipelineAst]
    }, $true) | ForEach-Object {
        $pipelineCommands = @(
            $_.PipelineElements | Where-Object {
                $_ -is [System.Management.Automation.Language.CommandAst]
            } | ForEach-Object { Convert-GuardCommand $_ }
        )
        if ($pipelineCommands.Count -gt 1) {
            [pscustomobject] [ordered] @{ commands = @($pipelineCommands) }
        }
    }
)

$redirections = @(
    $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FileRedirectionAst]
    }, $true) | ForEach-Object {
        [pscustomobject] [ordered] @{ target = Convert-GuardValue $_.Location }
    }
)

$hasAssignment = @(
    $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true)
).Count -gt 0

$hasChain = @(
    $ast.FindAll({
        param($node)
        $node.GetType().Name -eq 'PipelineChainAst'
    }, $true)
).Count -gt 0

$singleDirectCommand = $false
if ($parseErrors.Count -eq 0 -and $ast.EndBlock.Statements.Count -eq 1) {
    $statement = $ast.EndBlock.Statements[0]
    if ($statement -is [System.Management.Automation.Language.PipelineAst] -and $statement.PipelineElements.Count -eq 1 -and $statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
        $singleDirectCommand = $true
    }
}

$result = [pscustomobject] [ordered] @{
    parse_errors = @($parseErrors | ForEach-Object { [string] $_.Message })
    commands = @($commands)
    pipelines = @($pipelines)
    redirections = @($redirections)
    single_direct_command = $singleDirectCommand
    statement_count = [int] $ast.EndBlock.Statements.Count
    has_assignment = $hasAssignment
    has_chain = $hasChain
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$encodedResult = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
[Console]::Out.Write($encodedResult)
`

func (a *analyzer) analyzePowerShellSource(source string, depth int) {
	if depth > 4 {
		a.add(Review, "nested-shell-depth", "powershell", "")
		return
	}
	document, err := parsePowerShell(source)
	if err != nil {
		a.add(Review, "shell-parser-unavailable", "powershell", "")
		return
	}
	if len(document.ParseErrors) > 0 {
		a.add(Review, "shell-parse-risk", "powershell", "")
	}
	previousEligibility := a.protectedGitExceptionEligibility
	a.protectedGitExceptionEligibility = eligiblePowerShellProtectedGitException(document, depth)
	defer func() { a.protectedGitExceptionEligibility = previousEligibility }()
	for _, command := range document.Commands {
		a.inspectPowerShellCommand(command, depth)
	}
	for _, pipeline := range document.Pipelines {
		a.inspectPowerShellPipeline(pipeline)
	}
	for _, redirection := range document.Redirections {
		if !redirection.Target.Known {
			a.add(Review, "dynamic-protected-write", "redirect", "dynamic")
			continue
		}
		if a.protectedPath(redirection.Target.Value) {
			a.add(Block, "protected-redirection", "redirect", a.normalizePath(redirection.Target.Value))
		}
	}
}

func eligiblePowerShellProtectedGitException(document powerShellDocument, depth int) protectedGitExceptionEligibility {
	if depth != 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	if len(document.ParseErrors) > 0 {
		return protectedGitExceptionEligibility{}
	}
	if document.HasAssignment {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	if document.StatementCount > 1 || document.HasChain {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionCompoundCommand}
	}
	if len(document.Pipelines) > 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionPipeline}
	}
	if len(document.Redirections) > 0 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionRedirection}
	}
	if len(document.Commands) > 1 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionCompoundCommand}
	}
	if !document.SingleDirectCommand || len(document.Commands) != 1 {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	command := document.Commands[0]
	if !command.NameKnown {
		return protectedGitExceptionEligibility{}
	}
	if normalizeCommandName(command.Name) != "git" {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	invocationOperator := strings.ToLower(command.InvocationOperator)
	if invocationOperator != "" && invocationOperator != "unknown" {
		return protectedGitExceptionEligibility{Reason: protectedGitExceptionIndirect}
	}
	for _, element := range command.Elements {
		if !element.Known {
			return protectedGitExceptionEligibility{}
		}
	}
	return protectedGitExceptionEligibility{Eligible: true, Reason: protectedGitExceptionEligible}
}

func parsePowerShell(source string) (powerShellDocument, error) {
	executable, err := findPowerShell()
	if err != nil {
		return powerShellDocument{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", powerShellParserScript)
	command.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString([]byte(source)))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return powerShellDocument{}, fmt.Errorf("PowerShell parser timed out: %w", ctx.Err())
		}
		return powerShellDocument{}, fmt.Errorf("PowerShell parser failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	encoded := strings.TrimSpace(stdout.String())
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return powerShellDocument{}, fmt.Errorf("decode PowerShell parser output: %w", err)
	}
	var document powerShellDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return powerShellDocument{}, fmt.Errorf("parse PowerShell parser output: %w", err)
	}
	return document, nil
}

func findPowerShell() (string, error) {
	if override := os.Getenv("AGENT_COMMAND_GUARD_POWERSHELL"); override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("AGENT_COMMAND_GUARD_POWERSHELL must be an absolute path")
		}
		if info, err := os.Stat(override); err == nil && !info.IsDir() {
			return override, nil
		}
		return "", fmt.Errorf("AGENT_COMMAND_GUARD_POWERSHELL does not name an executable file: %q", override)
	}
	if runtime.GOOS == "windows" {
		candidates := make([]string, 0, 2)
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			candidates = append(candidates, filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe"))
		}
		if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
			candidates = append(candidates, filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	for _, name := range []string{"pwsh", "powershell"} {
		path, err := exec.LookPath(name)
		if err == nil && filepath.IsAbs(path) {
			return path, nil
		}
	}
	return "", errors.New("PowerShell executable not found")
}

func (a *analyzer) inspectPowerShellCommand(command powerShellCommand, depth int) {
	if !command.NameKnown {
		a.add(Review, "dynamic-command-name", "powershell", "")
		return
	}
	rawName := command.Name
	name := canonicalPowerShellCommand(rawName)
	args, known := powerShellArgv(command.Elements)
	if (name == "curl" || name == "wget") && powerShellHasParameter(command, "infile") {
		a.add(Block, "file-upload", name, "")
	}

	if strings.EqualFold(command.InvocationOperator, "Dot") {
		a.add(Review, "dynamic-code-gateway", name, "")
	}

	switch name {
	case "remove-item":
		a.inspectPowerShellRemoveItem(command)
	case "set-content", "add-content", "out-file", "tee-object", "export-clixml", "export-csv":
		a.inspectPowerShellWrites(name, command, map[string]bool{"value": true, "encoding": true, "width": true, "variable": true})
	case "clear-content", "clear-item", "clear-itemproperty", "set-item", "set-itemproperty", "new-itemproperty", "remove-itemproperty", "set-acl":
		a.inspectPowerShellWrites(name, command, nil)
	case "copy-item":
		a.inspectPowerShellDestination(name, command)
	case "move-item", "rename-item":
		a.inspectPowerShellWrites(name, command, nil)
	case "new-item":
		a.inspectPowerShellWrites(name, command, map[string]bool{"itemtype": true, "type": true, "value": true})
	case "icacls", "takeown":
		a.inspectPowerShellWrites(name, command, nil)
	case "get-content", "get-item", "get-childitem", "select-string", "import-clixml", "import-csv":
		a.inspectPowerShellReads(name, command)
	case "invoke-expression":
		a.add(Review, "dynamic-code-gateway", name, "")
	case "add-type":
		a.add(Review, "inline-interpreter-code", name, "")
	case "invoke-webrequest", "invoke-restmethod":
		if powerShellHasParameter(command, "infile") {
			a.add(Block, "file-upload", name, "")
		}
		a.inspectPowerShellNamedWrite(name, command, "outfile")
	case "start-bitstransfer":
		a.inspectPowerShellNamedWrite(name, command, "destination")
		a.add(Review, "remote-file-transfer", name, "")
	case "publish-module", "publish-script", "publish-psresource":
		a.add(Block, "package-publish", name, "")
	case "stop-computer", "restart-computer", "format-volume", "clear-disk", "initialize-disk", "remove-partition",
		"set-executionpolicy", "enable-psremoting", "disable-psremoting", "register-scheduledtask", "unregister-scheduledtask",
		"new-service", "remove-service", "remove-localuser", "remove-localgroup", "disable-localuser",
		"format", "diskpart", "bcdedit", "regedit", "vssadmin", "wbadmin":
		a.add(Block, "sensitive-system-command", name, "")
	case "reg":
		if powerShellHasArgument(command, "add", "delete", "import", "restore", "save", "unload") {
			a.add(Block, "sensitive-system-command", name, "")
		}
	case "sc":
		if powerShellHasArgument(command, "create", "delete", "config", "failure", "sdset") {
			a.add(Block, "sensitive-system-command", name, "")
		}
	case "invoke-command", "enter-pssession", "new-pssession":
		a.add(Review, "indirect-execution-gateway", name, "")
	case "start-process":
		if powerShellStartsExecutionGateway(command) {
			a.add(Review, "indirect-execution-gateway", name, "")
		}
	case "powershell", "pwsh":
		a.inspectNestedPowerShell(args, known, depth)
	case "cmd":
		if powerShellHasArgument(command, "/c", "/k") {
			a.add(Review, "indirect-execution-gateway", name, "")
		}
	default:
		argv := append([]string{rawName}, args...)
		argvKnown := append([]bool{true}, known...)
		a.inspectCommand(argv, argvKnown, depth)
	}
}

func (a *analyzer) inspectPowerShellRemoveItem(command powerShellCommand) {
	values := powerShellPathValues(command, map[string]bool{
		"filter": true, "include": true, "exclude": true, "erroraction": true,
		"warningaction": true, "informationaction": true, "progressaction": true,
	})
	recursive := powerShellHasParameter(command, "recurse")
	if len(values) == 0 {
		a.add(Review, "dynamic-recursive-delete", "remove-item", "dynamic")
		return
	}
	for _, value := range values {
		if !value.Known {
			a.add(Review, "dynamic-recursive-delete", "remove-item", "dynamic")
			continue
		}
		if sensitivePowerShellProvider(value.Value) {
			a.add(Block, "sensitive-system-command", "remove-item", value.Value)
			continue
		}
		target := a.normalizePath(value.Value)
		if recursive {
			if a.dangerousDeleteTarget(target) || a.dangerousGlobTarget(target) {
				a.add(Block, "recursive-delete-protected", "remove-item", target)
			}
		} else if a.dangerousDeleteTarget(target) {
			a.add(Block, "protected-delete", "remove-item", target)
		} else if isSigningKey(value.Value) {
			a.add(Review, "signing-key-delete", "remove-item", target)
		}
	}
}

func (a *analyzer) inspectPowerShellWrites(name string, command powerShellCommand, excluded map[string]bool) {
	values := powerShellPathValues(command, excluded)
	if len(values) == 0 {
		a.add(Review, "dynamic-protected-write", name, "dynamic")
		return
	}
	for _, value := range values {
		if !value.Known {
			a.add(Review, "dynamic-protected-write", name, "dynamic")
			continue
		}
		if sensitivePowerShellProvider(value.Value) {
			a.add(Block, "sensitive-system-command", name, value.Value)
		} else if a.protectedPath(value.Value) {
			a.add(Block, "guard-self-protection", name, a.normalizePath(value.Value))
		}
	}
}

func (a *analyzer) inspectPowerShellDestination(name string, command powerShellCommand) {
	if value, ok := powerShellNamedValue(command, "destination"); ok {
		if !value.Known {
			a.add(Review, "dynamic-protected-write", name, "dynamic")
		} else if a.protectedPath(value.Value) {
			a.add(Block, "guard-self-protection", name, a.normalizePath(value.Value))
		}
		return
	}
	values := powerShellPositionalValues(command, map[string]bool{
		"force": true, "recurse": true, "passthru": true, "confirm": true, "whatif": true,
	})
	if len(values) == 0 {
		return
	}
	destination := values[len(values)-1]
	if !destination.Known {
		a.add(Review, "dynamic-protected-write", name, "dynamic")
	} else if a.protectedPath(destination.Value) {
		a.add(Block, "guard-self-protection", name, a.normalizePath(destination.Value))
	}
}

func (a *analyzer) inspectPowerShellNamedWrite(name string, command powerShellCommand, parameter string) {
	value, ok := powerShellNamedValue(command, parameter)
	if !ok {
		return
	}
	if !value.Known {
		a.add(Review, "dynamic-protected-write", name, "dynamic")
	} else if sensitivePowerShellProvider(value.Value) {
		a.add(Block, "sensitive-system-command", name, value.Value)
	} else if a.protectedPath(value.Value) {
		a.add(Block, "guard-self-protection", name, a.normalizePath(value.Value))
	}
}

func (a *analyzer) inspectPowerShellReads(name string, command powerShellCommand) {
	for _, value := range powerShellPathValues(command, map[string]bool{
		"filter": true, "include": true, "exclude": true, "pattern": true,
		"encoding": true, "erroraction": true,
	}) {
		if value.Known && a.sensitiveReadPath(value.Value) {
			a.add(Block, "sensitive-shell-read", name, a.normalizePath(value.Value))
		}
	}
}

func (a *analyzer) inspectNestedPowerShell(args []string, known []bool, depth int) {
	for index, arg := range args {
		if strings.HasPrefix(arg, "-") && powerShellParameterMatches(arg, "encodedcommand") {
			a.add(Review, "inline-interpreter-code", "powershell", "")
			return
		}
		if !strings.HasPrefix(arg, "-") || !powerShellParameterMatches(arg, "command") {
			continue
		}
		if index+1 >= len(args) || index+1 >= len(known) {
			a.add(Review, "dynamic-shell-code", "powershell", "")
			return
		}
		for _, valueKnown := range known[index+1:] {
			if !valueKnown {
				a.add(Review, "dynamic-shell-code", "powershell", "")
				return
			}
		}
		a.analyzePowerShellSource(strings.Join(args[index+1:], " "), depth+1)
		return
	}
}

func (a *analyzer) inspectPowerShellPipeline(pipeline powerShellPipeline) {
	for index, source := range pipeline.Commands {
		sourceName := canonicalPowerShellCommand(source.Name)
		for _, sink := range pipeline.Commands[index+1:] {
			sinkName := canonicalPowerShellCommand(sink.Name)
			if powerShellNetworkSource(sourceName) && powerShellCodeSink(sinkName) {
				a.add(Block, "download-to-shell", "pipeline", "")
			}
			if a.powerShellSensitiveSource(sourceName, source) && (powerShellNetworkSink(sinkName) || powerShellCodeSink(sinkName)) {
				a.add(Block, "sensitive-pipeline", "pipeline", "")
			}
		}
	}
}

func (a *analyzer) powerShellSensitiveSource(name string, command powerShellCommand) bool {
	if name == "get-secret" || name == "get-credential" {
		return true
	}
	if name != "get-content" && name != "get-item" && name != "get-childitem" {
		return false
	}
	for _, value := range powerShellPathValues(command, nil) {
		if value.Known && (a.sensitiveReadPath(value.Value) || strings.HasPrefix(strings.ToLower(value.Value), "env:")) {
			return true
		}
	}
	return false
}

func powerShellArgv(elements []powerShellElement) ([]string, []bool) {
	args := make([]string, 0, len(elements))
	known := make([]bool, 0, len(elements))
	for _, element := range elements {
		value := element.Value
		if !element.Known {
			value = element.Text
		}
		args = append(args, value)
		known = append(known, element.Known)
	}
	return args, known
}

func powerShellPathValues(command powerShellCommand, excluded map[string]bool) []wordValue {
	values := make([]wordValue, 0)
	parameter := ""
	for _, element := range command.Elements {
		if element.Kind == "parameter" {
			parameter = normalizePowerShellParameter(element.Value)
			continue
		}
		if parameter != "" && excluded[parameter] {
			parameter = ""
			continue
		}
		value := element.Value
		if !element.Known {
			value = element.Text
		}
		values = append(values, wordValue{Value: value, Known: element.Known})
		parameter = ""
	}
	return values
}

func powerShellPositionalValues(command powerShellCommand, switches map[string]bool) []wordValue {
	values := make([]wordValue, 0)
	parameterPending := false
	for _, element := range command.Elements {
		if element.Kind == "parameter" {
			parameterPending = !switches[normalizePowerShellParameter(element.Value)]
			continue
		}
		if parameterPending {
			parameterPending = false
			continue
		}
		value := element.Value
		if !element.Known {
			value = element.Text
		}
		values = append(values, wordValue{Value: value, Known: element.Known})
	}
	return values
}

func powerShellNamedValue(command powerShellCommand, name string) (wordValue, bool) {
	for index, element := range command.Elements {
		if element.Kind != "parameter" || !powerShellParameterMatches(element.Value, name) || index+1 >= len(command.Elements) {
			continue
		}
		value := command.Elements[index+1]
		if value.Kind == "parameter" {
			return wordValue{}, false
		}
		text := value.Value
		if !value.Known {
			text = value.Text
		}
		return wordValue{Value: text, Known: value.Known}, true
	}
	return wordValue{}, false
}

func powerShellHasParameter(command powerShellCommand, name string) bool {
	for _, element := range command.Elements {
		if element.Kind == "parameter" && powerShellParameterMatches(element.Value, name) {
			return true
		}
	}
	return false
}

func powerShellHasArgument(command powerShellCommand, values ...string) bool {
	for _, element := range command.Elements {
		if !element.Known {
			continue
		}
		for _, value := range values {
			if strings.EqualFold(element.Value, value) {
				return true
			}
		}
	}
	return false
}

func powerShellStartsExecutionGateway(command powerShellCommand) bool {
	for _, element := range command.Elements {
		if !element.Known {
			continue
		}
		switch canonicalPowerShellCommand(element.Value) {
		case "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta":
			return true
		}
	}
	return false
}

func normalizePowerShellParameter(value string) string {
	return strings.ToLower(strings.TrimLeft(value, "-"))
}

func powerShellParameterMatches(value, name string) bool {
	parameter := normalizePowerShellParameter(value)
	name = strings.ToLower(name)
	return parameter != "" && strings.HasPrefix(name, parameter)
}

func canonicalPowerShellCommand(command string) string {
	raw := strings.TrimSpace(command)
	name := normalizeCommandName(raw)
	if strings.ContainsAny(raw, `/\`) || strings.Contains(filepath.Base(raw), ".") {
		return name
	}
	aliases := map[string]string{
		"cat": "get-content", "gc": "get-content", "type": "get-content",
		"gci": "get-childitem", "dir": "get-childitem", "ls": "get-childitem",
		"gi": "get-item", "select": "select-object", "sls": "select-string",
		"rm": "remove-item", "ri": "remove-item", "del": "remove-item", "erase": "remove-item", "rd": "remove-item", "rmdir": "remove-item",
		"cp": "copy-item", "copy": "copy-item", "cpi": "copy-item",
		"mv": "move-item", "move": "move-item", "mi": "move-item",
		"ni": "new-item", "clc": "clear-content", "ac": "add-content", "sc": "set-content",
		"iex": "invoke-expression", "iwr": "invoke-webrequest", "irm": "invoke-restmethod",
		"saps": "start-process", "start": "start-process",
	}
	if canonical, ok := aliases[name]; ok {
		return canonical
	}
	return name
}

func powerShellNetworkSource(command string) bool {
	return command == "invoke-webrequest" || command == "invoke-restmethod" || command == "curl" || command == "wget"
}

func powerShellNetworkSink(command string) bool {
	return powerShellNetworkSource(command) || command == "start-bitstransfer" || command == "ssh" || command == "scp"
}

func powerShellCodeSink(command string) bool {
	return command == "invoke-expression" || command == "powershell" || command == "pwsh" || command == "cmd"
}

func sensitivePowerShellProvider(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return strings.HasPrefix(lower, "hklm:") || strings.HasPrefix(lower, "hkcu:") || strings.HasPrefix(lower, "registry::") ||
		strings.HasPrefix(lower, "cert:")
}
