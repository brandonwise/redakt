/**
 * PII detection patterns for redakt
 * Each pattern has a regex and a replacement function
 * Order matters - more specific patterns should come before generic ones
 */

/**
 * Built-in redaction patterns
 * Patterns are processed in order defined in defaultPatterns/allPatternNames
 * @type {Object.<string, {regex: RegExp, replace: function, description: string, priority: number}>}
 */
const patterns = {
  // Private keys (PEM format markers) - high priority, very specific
  privateKey: {
    regex:
      /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    replace: () => '[PRIVATE_KEY]',
    description: 'Private keys (PEM format)',
    priority: 10,
  },

  // JWT tokens - before bearer tokens
  jwt: {
    regex: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+/g,
    replace: () => '[JWT]',
    description: 'JSON Web Tokens',
    priority: 20,
  },

  // URLs with credentials - before email (which might match user@domain)
  urlWithCreds: {
    regex: /(?:https?|ftp):\/\/[^\s:]+:[^\s@]+@[^\s]+/gi,
    replace: (match) => {
      // Preserve domain but hide credentials
      return match.replace(/:\/\/[^\s:]+:[^\s@]+@/, '://[REDACTED]@');
    },
    description: 'URLs containing credentials',
    priority: 25,
  },

  // GitHub tokens (classic and fine-grained)
  githubToken: {
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    replace: () => '[GITHUB_TOKEN]',
    description: 'GitHub personal access tokens',
    priority: 30,
  },

  // Slack tokens - before phone (contains number sequences)
  slackToken: {
    regex: /\bxox[baprs]-\d+-\d+-[a-zA-Z0-9]+\b/g,
    replace: () => '[SLACK_TOKEN]',
    description: 'Slack tokens',
    priority: 35,
  },

  // AWS Access Key ID
  awsKey: {
    regex: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    replace: () => '[AWS_KEY]',
    description: 'AWS Access Key IDs',
    priority: 40,
  },

  // Generic API keys (Bearer tokens, Authorization headers)
  bearerToken: {
    regex: /\b(?:Bearer|Basic)\s+[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*\.?[A-Za-z0-9\-_.+/=]*/gi,
    replace: () => '[AUTH_TOKEN]',
    description: 'Bearer/Basic auth tokens',
    priority: 45,
  },

  // Credit card numbers (major brands with common formats) - before phone
  creditCard: {
    regex:
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b/g,
    replace: () => '[CREDIT_CARD]',
    description: 'Credit card numbers',
    priority: 50,
  },

  // Social Security Numbers - before phone
  ssn: {
    regex: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b|\b[0-9]{3}\s[0-9]{2}\s[0-9]{4}\b/g,
    replace: () => '[SSN]',
    description: 'Social Security Numbers',
    priority: 55,
  },

  // Email addresses
  email: {
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    replace: () => '[EMAIL]',
    description: 'Email addresses',
    priority: 60,
  },

  // Phone numbers (various formats) - after credit cards and SSN
  phone: {
    regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}\b/g,
    replace: () => '[PHONE]',
    description: 'Phone numbers (US format)',
    priority: 70,
  },

  // IPv4 addresses
  ipv4: {
    regex:
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    replace: () => '[IPv4]',
    description: 'IPv4 addresses',
    priority: 80,
  },

  // IPv6 addresses
  ipv6: {
    regex:
      /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
    replace: () => '[IPv6]',
    description: 'IPv6 addresses',
    priority: 85,
  },

  // AWS Secret Access Key (high entropy 40-char base64)
  awsSecret: {
    regex: /\b[A-Za-z0-9/+=]{40}\b/g,
    replace: (match) => {
      // Only redact if it looks like a real secret (not just random text)
      // Check for reasonable entropy
      const uniqueChars = new Set(match).size;
      if (uniqueChars > 15) {
        return '[AWS_SECRET]';
      }
      return match;
    },
    description: 'AWS Secret Access Keys',
    priority: 90,
  },

  // Generic hex secrets (32+ chars, looks like hash/key)
  hexSecret: {
    regex: /\b[a-fA-F0-9]{32,}\b/g,
    replace: (match) => {
      // Only redact if it's at least 32 chars (MD5 length or longer)
      if (match.length >= 32) {
        return '[HEX_SECRET]';
      }
      return match;
    },
    description: 'Hex-encoded secrets/hashes (32+ chars)',
    priority: 100,
  },
};

/**
 * Default patterns to enable (in priority order)
 */
const defaultPatterns = [
  'privateKey',
  'jwt',
  'urlWithCreds',
  'githubToken',
  'slackToken',
  'bearerToken',
  'creditCard',
  'ssn',
  'email',
  'phone',
  'ipv4',
];

/**
 * All available pattern names
 */
const allPatternNames = Object.keys(patterns);

module.exports = {
  patterns,
  defaultPatterns,
  allPatternNames,
};
