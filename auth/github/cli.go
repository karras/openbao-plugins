package github

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
)

type CLIHandler struct {
	// for tests
	testStdout io.Writer
}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount := h.getMountPath(m)
	token, err := h.getToken(m)
	if err != nil {
		return nil, err
	}

	return h.performLogin(c, mount, token)
}

// getMountPath retrieves the mount path from the configuration, defaulting to "github"
func (h *CLIHandler) getMountPath(m map[string]string) string {
	mount, ok := m["mount"]
	if !ok {
		mount = "github"
	}
	return mount
}

// getToken retrieves the GitHub token from config, environment, or interactive prompt
func (h *CLIHandler) getToken(m map[string]string) (string, error) {
	// Try to get token from configuration
	token := m["token"]
	if token != "" {
		return token, nil
	}

	// Try to get token from environment variable
	token = os.Getenv("VAULT_AUTH_GITHUB_TOKEN")
	if token != "" {
		return token, nil
	}

	// Prompt user for token interactively
	return h.promptForToken()
}

// promptForToken prompts the user to enter their GitHub token interactively
func (h *CLIHandler) promptForToken() (string, error) {
	stdout := h.getStdout()

	// Display prompt
	if err := h.writePrompt(stdout); err != nil {
		return "", err
	}

	// Read token from stdin (hidden)
	token, err := password.Read(os.Stdin)
	if err != nil {
		return "", h.handlePasswordReadError(err)
	}

	// Write newline after hidden input
	if err := h.writeNewline(stdout); err != nil {
		return "", err
	}

	return token, nil
}

// getStdout returns the output writer for prompts, defaulting to stderr
func (h *CLIHandler) getStdout() io.Writer {
	if h.testStdout != nil {
		return h.testStdout
	}
	return os.Stderr
}

// writePrompt writes the token prompt to the output
func (h *CLIHandler) writePrompt(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "GitHub Personal Access Token (will be hidden): "); err != nil {
		return fmt.Errorf("failed to write prompt: %w", err)
	}
	return nil
}

// writeNewline writes a newline after the hidden password input
func (h *CLIHandler) writeNewline(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	return nil
}

// handlePasswordReadError handles errors from reading password input
func (h *CLIHandler) handlePasswordReadError(err error) error {
	if err == password.ErrInterrupted {
		return fmt.Errorf("user interrupted")
	}

	return fmt.Errorf("an error occurred attempting to "+
		"ask for a token; the raw error message is shown below, but usually "+
		"this is because you attempted to pipe a value into the command or "+
		"you are executing outside of a terminal (tty); if you want to pipe "+
		"the value, pass \"-\" as the argument to read from stdin; the raw "+
		"error was: %w", err)
}

// performLogin executes the login request with the GitHub token
func (h *CLIHandler) performLogin(c *api.Client, mount, token string) (*api.Secret, error) {
	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, map[string]interface{}{
		"token": strings.TrimSpace(token),
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=github [CONFIG K=V...]

  The GitHub auth method allows users to authenticate using a GitHub
  personal access token. Users can generate a personal access token from the
  settings page on their GitHub account.

  Authenticate using a GitHub token:

      $ vault login -method=github token=abcd1234

Configuration:

  mount=<string>
      Path where the GitHub credential method is mounted. This is usually
      provided via the -path flag in the "vault login" command, but it can be
      specified here as well. If specified here, it takes precedence over the
      value for -path. The default value is "github".

  token=<string>
      GitHub personal access token to use for authentication. If not provided,
      Vault will prompt for the value.
`

	return strings.TrimSpace(help)
}
