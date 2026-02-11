# redakt

> CLI tool for detecting and masking PII in text — emails, phones, credit cards, IPs, API keys — pipe-friendly and zero-dependency

[![npm version](https://img.shields.io/npm/v/redakt.svg)](https://www.npmjs.com/package/redakt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why redakt?

Sharing logs, errors, or config files often means accidentally exposing sensitive data. **redakt** makes it safe and simple:

- 🔒 **Redact PII** - Emails, phones, SSNs, credit cards, IPs
- 🔑 **Mask secrets** - API keys, JWT tokens, private keys
- 🔗 **Pipe-friendly** - Works with stdin/stdout for Unix workflows
- 📦 **Zero dependencies** - Fast, lightweight, no supply chain risk
- 🛡️ **Offline** - Your data never leaves your machine

## Installation

```bash
# npm
npm install -g redakt

# Or use directly with npx
npx redakt < file.log
```

## Quick Start

```bash
# Redact a log file
redakt server.log > sanitized.log

# Pipe from another command
cat error.log | redakt

# Pipe from clipboard (macOS)
pbpaste | redakt | pbcopy

# Detection mode - just report what's sensitive
redakt -d sensitive.txt
```

## Usage

```
redakt [options] [file]
cat file | redakt

OPTIONS:
  -h, --help              Show help
  -v, --version           Show version
  -l, --list              List available patterns
  -d, --detect            Detection mode (don't redact, just report)
  -s, --stats             Show redaction statistics
  -q, --quiet             Suppress status messages (output only)
  -a, --all               Enable all patterns (including extras)
  -i, --include <p,...>   Include only these patterns (comma-separated)
  -x, --exclude <p,...>   Exclude these patterns (comma-separated)
  -o, --output <file>     Write output to file (default: stdout)
```

## Examples

### Basic redaction

```bash
$ echo "Contact me at john@example.com or 555-123-4567" | redakt
Contact me at [EMAIL] or [PHONE]
```

### With statistics

```bash
$ redakt -s logs.txt
Connection from 192.168.1.100
User logged in: [EMAIL]
Payment with card: [CREDIT_CARD]

📊 Redacted 3 item(s):
   email: 1
   creditCard: 1
   ipv4: 1
```

### Detection mode

```bash
$ redakt -d config.yml

⚠️  Found 2 sensitive item(s):

  githubToken (1)
    GitHub personal access tokens
    Samples: ghp...xyz

  bearerToken (1)
    Bearer/Basic auth tokens
    Samples: Bea...abc
```

### Select specific patterns

```bash
# Only redact emails and phones
redakt -i email,phone data.txt

# Redact everything except IP addresses
redakt -x ipv4 logs.txt
```

## Patterns

### Default patterns (always on)

| Pattern | Description | Example |
|---------|-------------|---------|
| `email` | Email addresses | `john@example.com` → `[EMAIL]` |
| `phone` | Phone numbers (US) | `555-123-4567` → `[PHONE]` |
| `creditCard` | Credit card numbers | `4111111111111111` → `[CREDIT_CARD]` |
| `ssn` | Social Security Numbers | `123-45-6789` → `[SSN]` |
| `ipv4` | IPv4 addresses | `192.168.1.1` → `[IPv4]` |
| `bearerToken` | Bearer/Basic auth | `Bearer xyz123` → `[AUTH_TOKEN]` |
| `jwt` | JSON Web Tokens | `eyJhbG...` → `[JWT]` |
| `urlWithCreds` | URLs with credentials | `https://user:pass@host` → `https://[REDACTED]@host` |
| `githubToken` | GitHub tokens | `ghp_xxx...` → `[GITHUB_TOKEN]` |
| `slackToken` | Slack tokens | `xoxb-...` → `[SLACK_TOKEN]` |
| `privateKey` | PEM private keys | `-----BEGIN PRIVATE KEY-----...` → `[PRIVATE_KEY]` |

### Extra patterns (use `-a` or `--all`)

| Pattern | Description |
|---------|-------------|
| `ipv6` | IPv6 addresses |
| `awsKey` | AWS Access Key IDs |
| `awsSecret` | AWS Secret Access Keys |
| `hexSecret` | Hex-encoded secrets (32+ chars) |

## Programmatic API

```javascript
const { redact, detect, listPatterns } = require('redakt');

// Basic redaction
const result = redact('Email: john@example.com');
console.log(result.text); // "Email: [EMAIL]"

// With options and stats
const { text, stats } = redact(input, {
  include: ['email', 'phone'],
  stats: true,
});
console.log(stats); // { total: 3, byType: { email: 2, phone: 1 } }

// Detection only
const info = detect('Contact: 555-123-4567');
if (info.hasSensitiveData) {
  console.log(info.matches);
}

// List available patterns
const patterns = listPatterns();
```

## Use Cases

- **Sharing logs with AI assistants** - Sanitize before pasting to ChatGPT/Claude
- **Debugging with colleagues** - Share stack traces safely
- **CI/CD pipelines** - Sanitize build logs before publishing
- **Compliance** - GDPR/privacy requirements for log storage
- **Security audits** - Detect secrets in codebases

## License

MIT © Brandon Wise
