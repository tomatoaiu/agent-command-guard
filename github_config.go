package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const defaultGitHubHost = "github.com"

type GitHubConfig struct {
	PullRequestCreateBlocks []GitHubPullRequestCreateBlock `toml:"pull_request_create_blocks"`
}

// GitHubPullRequestCreateBlock identifies one repository where commands that
// create pull requests are refused. Repository identities are configured
// independently from local checkout paths so the policy follows clones and
// linked worktrees without disclosing or querying repository visibility.
type GitHubPullRequestCreateBlock struct {
	Host       string `toml:"host"`
	Repository string `toml:"repository"`

	identity githubRepositoryIdentity
}

type githubRepositoryIdentity struct {
	Host  string
	Owner string
	Name  string
}

func (i githubRepositoryIdentity) String() string {
	if i.Host == "" || i.Owner == "" || i.Name == "" {
		return ""
	}
	return i.Host + "/" + i.Owner + "/" + i.Name
}

func (i githubRepositoryIdentity) key() string {
	return strings.ToLower(i.String())
}

func prepareGitHubPullRequestCreateBlocks(blocks []GitHubPullRequestCreateBlock) error {
	seen := make(map[string]bool, len(blocks))
	for i := range blocks {
		block := &blocks[i]
		label := fmt.Sprintf("github.pull_request_create_blocks[%d]", i)
		identity, err := configuredGitHubRepositoryIdentity(block.Host, block.Repository)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if seen[identity.key()] {
			return fmt.Errorf("%s is a duplicate of an earlier repository", label)
		}
		seen[identity.key()] = true
		block.Host = identity.Host
		block.Repository = identity.Owner + "/" + identity.Name
		block.identity = identity
	}
	return nil
}

func configuredGitHubRepositoryIdentity(host, repository string) (githubRepositoryIdentity, error) {
	normalizedHost, err := normalizeGitHubHost(host)
	if err != nil {
		return githubRepositoryIdentity{}, fmt.Errorf("host: %w", err)
	}
	owner, name, err := normalizeGitHubRepositoryName(repository)
	if err != nil {
		return githubRepositoryIdentity{}, fmt.Errorf("repository: %w", err)
	}
	return githubRepositoryIdentity{Host: normalizedHost, Owner: owner, Name: name}, nil
}

func normalizeGitHubHost(host string) (string, error) {
	if host == "" {
		return defaultGitHubHost, nil
	}
	if strings.TrimSpace(host) != host || strings.Contains(host, "://") || strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("must be a hostname, got %q", host)
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("must be a hostname, got %q", host)
	}
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), " \\/@?#") || !validGitHubHostname(parsed.Hostname()) {
		return "", fmt.Errorf("must be a hostname, got %q", host)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", fmt.Errorf("has an invalid port, got %q", host)
		}
	}
	return canonicalGitHubHost(strings.ToLower(strings.TrimSuffix(parsed.Host, "."))), nil
}

func validGitHubHostname(hostname string) bool {
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	if hostname == "" {
		return false
	}
	if net.ParseIP(hostname) != nil {
		return true
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || !asciiAlphaNumeric(rune(label[0])) || !asciiAlphaNumeric(rune(label[len(label)-1])) {
			return false
		}
		for _, character := range label {
			if !asciiAlphaNumeric(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func normalizeGitHubRepositoryName(repository string) (string, string, error) {
	if strings.TrimSpace(repository) != repository {
		return "", "", fmt.Errorf("must use the exact OWNER/REPOSITORY form")
	}
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || !validGitHubOwner(parts[0]) || !validGitHubRepository(parts[1]) {
		return "", "", fmt.Errorf("must use the exact OWNER/REPOSITORY form")
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), nil
}

func validGitHubOwner(value string) bool {
	if value == "" || !asciiAlphaNumeric(rune(value[0])) || !asciiAlphaNumeric(rune(value[len(value)-1])) {
		return false
	}
	for _, character := range value {
		if !asciiAlphaNumeric(character) && character != '-' {
			return false
		}
	}
	return true
}

func validGitHubRepository(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func canonicalGitHubHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	hostname := host
	port := ""
	if parsed, err := url.Parse("https://" + host); err == nil && parsed.Hostname() != "" {
		hostname = strings.ToLower(parsed.Hostname())
		port = parsed.Port()
	}
	if hostname == "api.github.com" || hostname == "ssh.github.com" {
		return defaultGitHubHost
	}
	if port == "22" || port == "80" || port == "443" {
		port = ""
	}
	if strings.Contains(hostname, ":") {
		if port != "" {
			return net.JoinHostPort(hostname, port)
		}
		return "[" + hostname + "]"
	}
	if port != "" {
		return hostname + ":" + port
	}
	return hostname
}

func (b GitHubPullRequestCreateBlock) repositoryIdentity() (githubRepositoryIdentity, bool) {
	if b.identity.String() != "" {
		return b.identity, true
	}
	identity, err := configuredGitHubRepositoryIdentity(b.Host, b.Repository)
	return identity, err == nil
}
