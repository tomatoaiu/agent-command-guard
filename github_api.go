package main

import (
	"net/url"
	"strings"
)

type ghAPIInvocation struct {
	endpoint        string
	endpointSeen    bool
	endpointKnown   bool
	host            string
	hostKnown       bool
	method          string
	methodKnown     bool
	hasFields       bool
	hasInput        bool
	help            bool
	queries         []wordValue
	queryUnresolved bool
}

func (a *analyzer) inspectGitHubAPI(args []string, known []bool) {
	defaultHost, hostKnown := a.defaultGitHubHost()
	invocation := parseGhAPIInvocation(args, known, defaultHost, hostKnown)
	if invocation.help {
		return
	}
	method := "GET"
	methodKnown := true
	if invocation.hasFields {
		method = "POST"
	}
	if invocation.method != "" || !invocation.methodKnown {
		method = strings.ToUpper(invocation.method)
		methodKnown = invocation.methodKnown
	}
	if definitelyReadOnlyHTTPMethod(method, methodKnown) {
		return
	}
	if !invocation.endpointSeen || !invocation.endpointKnown {
		a.add(Block, "github-pull-request-operation-unknown", "gh", "dynamic API endpoint")
		return
	}

	identity, placeholders, matched, targetKnown := gitHubPullRequestEndpoint(invocation.endpoint, invocation.host, invocation.hostKnown)
	if matched {
		if !targetKnown {
			a.add(Block, "github-pull-request-target-unknown", "gh", "dynamic")
			return
		}
		if placeholders {
			a.blockGitHubPullRequestTarget(nil, nil)
			return
		}
		if a.blocksGitHubPullRequestCreation(identity) {
			a.add(Block, "github-pull-request-create", "gh", identity.String())
		}
		return
	}

	if gitHubGraphQLEndpoint(invocation.endpoint) {
		for _, query := range invocation.queries {
			if query.Known && graphQLCreatesPullRequest(query.Value) {
				// createPullRequest identifies its base repository by node ID, so
				// an offline OWNER/REPOSITORY policy cannot distinguish entries.
				// Blocking the explicit mutation is the only fail-closed result.
				a.add(Block, "github-pull-request-create", "gh", "graphql")
				return
			}
		}
		if invocation.queryUnresolved || invocation.hasInput {
			a.add(Block, "github-pull-request-operation-unknown", "gh", "dynamic GraphQL mutation")
		}
	}
}

func definitelyReadOnlyHTTPMethod(method string, known bool) bool {
	if !known {
		return false
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func parseGhAPIInvocation(args []string, known []bool, defaultHost string, defaultHostKnown bool) ghAPIInvocation {
	invocation := ghAPIInvocation{host: defaultHost, hostKnown: defaultHostKnown, methodKnown: true}
	endOptions := false
	for i := 0; i < len(args); i++ {
		argKnown := i < len(known) && known[i]
		arg := args[i]
		if !argKnown {
			if !invocation.endpointSeen {
				invocation.endpointSeen = true
				invocation.endpointKnown = false
			}
			continue
		}
		if !endOptions && arg == "--" {
			endOptions = true
			continue
		}
		if !endOptions && (arg == "--help" || arg == "-h") {
			invocation.help = true
			continue
		}
		if !endOptions {
			switch {
			case arg == "-X" || arg == "--method":
				value, valueKnown := nextGhArgument(args, known, &i)
				invocation.method, invocation.methodKnown = value, valueKnown
				continue
			case strings.HasPrefix(arg, "--method="):
				invocation.method = strings.TrimPrefix(arg, "--method=")
				continue
			case strings.HasPrefix(arg, "-X") && len(arg) > 2:
				invocation.method = arg[2:]
				continue
			case arg == "--hostname":
				value, valueKnown := nextGhArgument(args, known, &i)
				if valueKnown {
					host, err := normalizeGitHubHost(value)
					invocation.host, invocation.hostKnown = host, err == nil
				} else {
					invocation.hostKnown = false
				}
				continue
			case strings.HasPrefix(arg, "--hostname="):
				host, err := normalizeGitHubHost(strings.TrimPrefix(arg, "--hostname="))
				invocation.host, invocation.hostKnown = host, err == nil
				continue
			case ghAPIFieldFlag(arg):
				value, valueKnown := ghAPIFieldValue(arg, args, known, &i)
				invocation.hasFields = true
				if query, ok := githubAPIQueryField(value, valueKnown); ok {
					invocation.queries = append(invocation.queries, query)
					invocation.queryUnresolved = invocation.queryUnresolved || !query.Known
				}
				continue
			case arg == "--input":
				_, _ = nextGhArgument(args, known, &i)
				invocation.hasInput = true
				continue
			case strings.HasPrefix(arg, "--input="):
				invocation.hasInput = true
				continue
			case ghAPIOptionTakesValue(arg):
				_, _ = nextGhArgument(args, known, &i)
				continue
			case strings.HasPrefix(arg, "-"):
				continue
			}
		}
		if !invocation.endpointSeen {
			invocation.endpoint = arg
			invocation.endpointSeen = true
			invocation.endpointKnown = true
		}
	}
	return invocation
}

func nextGhArgument(args []string, known []bool, index *int) (string, bool) {
	(*index)++
	if *index >= len(args) || *index >= len(known) || !known[*index] {
		return "", false
	}
	return args[*index], true
}

func ghAPIFieldFlag(arg string) bool {
	return arg == "-f" || arg == "--raw-field" || arg == "-F" || arg == "--field" ||
		strings.HasPrefix(arg, "--raw-field=") || strings.HasPrefix(arg, "--field=") ||
		strings.HasPrefix(arg, "-f") && len(arg) > 2 || strings.HasPrefix(arg, "-F") && len(arg) > 2
}

func ghAPIFieldValue(arg string, args []string, known []bool, index *int) (string, bool) {
	switch {
	case arg == "-f" || arg == "--raw-field" || arg == "-F" || arg == "--field":
		return nextGhArgument(args, known, index)
	case strings.HasPrefix(arg, "--raw-field="):
		return strings.TrimPrefix(arg, "--raw-field="), true
	case strings.HasPrefix(arg, "--field="):
		return strings.TrimPrefix(arg, "--field="), true
	default:
		return arg[2:], true
	}
}

func ghAPIOptionTakesValue(arg string) bool {
	switch arg {
	case "--cache", "-H", "--header", "-q", "--jq", "-p", "--preview", "-t", "--template":
		return true
	default:
		return false
	}
}

func githubAPIQueryField(value string, known bool) (wordValue, bool) {
	if !known {
		return wordValue{Known: false}, true
	}
	name, query, ok := strings.Cut(value, "=")
	if !ok || name != "query" {
		return wordValue{}, false
	}
	if strings.HasPrefix(query, "@") {
		return wordValue{Known: false}, true
	}
	return wordValue{Value: query, Known: true}, true
}

func gitHubPullRequestEndpoint(endpoint, defaultHost string, hostKnown bool) (githubRepositoryIdentity, bool, bool, bool) {
	host := defaultHost
	path := endpoint
	if parsed, err := url.Parse(endpoint); err == nil {
		path = parsed.EscapedPath()
		if parsed.IsAbs() {
			host = parsed.Host
			hostKnown = parsed.Hostname() != ""
		}
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	path = strings.Trim(path, "/")
	if strings.HasPrefix(path, "api/v3/") {
		path = strings.TrimPrefix(path, "api/v3/")
	}
	parts := strings.Split(path, "/")
	if len(parts) != 4 || parts[0] != "repos" || parts[3] != "pulls" {
		return githubRepositoryIdentity{}, false, false, false
	}
	if !hostKnown {
		return githubRepositoryIdentity{}, false, true, false
	}
	normalizedHost, err := normalizeGitHubHost(host)
	if err != nil {
		return githubRepositoryIdentity{}, false, true, false
	}
	if parts[1] == "{owner}" && parts[2] == "{repo}" {
		return githubRepositoryIdentity{}, true, true, true
	}
	owner, name, err := normalizeGitHubRepositoryName(parts[1] + "/" + parts[2])
	if err != nil {
		return githubRepositoryIdentity{}, false, true, false
	}
	return githubRepositoryIdentity{Host: normalizedHost, Owner: owner, Name: name}, false, true, true
}

func gitHubGraphQLEndpoint(endpoint string) bool {
	path := endpoint
	if parsed, err := url.Parse(endpoint); err == nil {
		path = parsed.Path
	}
	path = strings.Trim(path, "/")
	return strings.EqualFold(path, "graphql") || strings.EqualFold(path, "api/graphql")
}

func graphQLCreatesPullRequest(query string) bool {
	lower := strings.ToLower(query)
	return strings.Contains(lower, "mutation") && strings.Contains(lower, "createpullrequest")
}
