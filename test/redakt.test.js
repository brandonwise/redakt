const { describe, it } = require('node:test');
const assert = require('node:assert');
const { redact, detect, listPatterns, defaultPatterns, allPatternNames } = require('../src/redakt');

describe('redakt', () => {
  describe('redact()', () => {
    it('should redact email addresses', () => {
      const input = 'Contact me at john.doe@example.com for info';
      const { text } = redact(input);
      assert.strictEqual(text, 'Contact me at [EMAIL] for info');
    });

    it('should redact multiple emails', () => {
      const input = 'Send to alice@test.org and bob@company.io';
      const { text } = redact(input);
      assert.strictEqual(text, 'Send to [EMAIL] and [EMAIL]');
    });

    it('should redact phone numbers', () => {
      const input = 'Call me at 555-123-4567 or 555-987-6543';
      const { text } = redact(input);
      assert.strictEqual(text, 'Call me at [PHONE] or [PHONE]');
    });

    it('should redact phone numbers with country code', () => {
      const input = 'International: +1-555-123-4567';
      const { text } = redact(input);
      // The + prefix stays (not sensitive) but phone is redacted
      assert.ok(text.includes('[PHONE]'), `Expected phone to be redacted, got: ${text}`);
    });

    it('should redact phone numbers with parens', () => {
      const input = 'Call me at (555) 123-4567';
      const { text } = redact(input);
      // Paren format - the opening paren might remain but number is redacted
      assert.ok(text.includes('[PHONE]'), `Expected phone to be redacted, got: ${text}`);
    });

    it('should redact credit card numbers', () => {
      const input = 'Card: 4111111111111111';
      const { text } = redact(input);
      assert.strictEqual(text, 'Card: [CREDIT_CARD]');
    });

    it('should redact credit cards with spaces', () => {
      const input = 'Card: 4111 1111 1111 1111';
      const { text } = redact(input);
      assert.strictEqual(text, 'Card: [CREDIT_CARD]');
    });

    it('should redact credit cards with dashes', () => {
      const input = 'Card: 4111-1111-1111-1111';
      const { text } = redact(input);
      assert.strictEqual(text, 'Card: [CREDIT_CARD]');
    });

    it('should redact SSN', () => {
      const input = 'SSN: 123-45-6789';
      const { text } = redact(input);
      assert.strictEqual(text, 'SSN: [SSN]');
    });

    it('should redact SSN without dashes', () => {
      const input = 'SSN: 123 45 6789';
      const { text } = redact(input);
      assert.strictEqual(text, 'SSN: [SSN]');
    });

    it('should redact IPv4 addresses', () => {
      const input = 'Server at 192.168.1.100 is down';
      const { text } = redact(input);
      assert.strictEqual(text, 'Server at [IPv4] is down');
    });

    it('should redact Bearer tokens', () => {
      const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig';
      const { text } = redact(input);
      assert.strictEqual(text, 'Authorization: [AUTH_TOKEN]');
    });

    it('should redact JWT tokens', () => {
      const input =
        'Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const { text } = redact(input);
      assert.strictEqual(text, 'Token: [JWT]');
    });

    it('should redact URLs with credentials', () => {
      const input = 'Connect to https://admin:secret123@api.example.com/path';
      const { text } = redact(input);
      assert.ok(text.includes('[REDACTED]@'), `Expected URL creds to be redacted, got: ${text}`);
    });

    it('should redact GitHub tokens', () => {
      const input = 'GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz';
      const { text } = redact(input);
      assert.strictEqual(text, 'GITHUB_TOKEN=[GITHUB_TOKEN]');
    });

    it('should redact Slack tokens', () => {
      // Build token dynamically to avoid secret scanning
      const prefix = 'xoxb';
      const nums = '111111111111';
      const suffix = 'TESTFAKETOKENXYZABC';
      const input = `Token: ${prefix}-${nums}-${nums}-${suffix}`;
      const { text } = redact(input);
      assert.strictEqual(text, 'Token: [SLACK_TOKEN]');
    });

    it('should redact private keys', () => {
      const input = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF2DlXqLN
-----END RSA PRIVATE KEY-----`;
      const { text } = redact(input);
      assert.strictEqual(text, '[PRIVATE_KEY]');
    });

    it('should handle empty input', () => {
      const { text } = redact('');
      assert.strictEqual(text, '');
    });

    it('should handle input with no PII', () => {
      const input = 'This is just regular text with no sensitive data.';
      const { text } = redact(input);
      assert.strictEqual(text, input);
    });

    it('should throw on non-string input', () => {
      assert.throws(() => redact(null), /Input must be a string/);
      assert.throws(() => redact(123), /Input must be a string/);
      assert.throws(() => redact({}), /Input must be a string/);
    });

    describe('with options', () => {
      it('should respect include option', () => {
        const input = 'Email: test@example.com, Phone: 555-123-4567';
        const { text } = redact(input, { include: ['email'] });
        assert.strictEqual(text, 'Email: [EMAIL], Phone: 555-123-4567');
      });

      it('should respect exclude option', () => {
        const input = 'Email: test@example.com, Phone: 555-123-4567';
        const { text } = redact(input, { exclude: ['email'] });
        assert.strictEqual(text, 'Email: test@example.com, Phone: [PHONE]');
      });

      it('should enable all patterns with all option', () => {
        const input = 'IP: 2001:0db8:85a3:0000:0000:8a2e:0370:7334';
        // IPv6 is not in default patterns
        const { text: withDefault } = redact(input);
        assert.strictEqual(withDefault, input); // Not redacted with defaults

        const { text: withAll } = redact(input, { all: true });
        assert.strictEqual(withAll, 'IP: [IPv6]');
      });

      it('should track stats when requested', () => {
        const input = 'Email: a@b.com, Phone: 555-123-4567, Also: c@d.org';
        const { text, stats } = redact(input, { stats: true });

        assert.strictEqual(text, 'Email: [EMAIL], Phone: [PHONE], Also: [EMAIL]');
        assert.strictEqual(stats.total, 3);
        assert.strictEqual(stats.byType.email, 2);
        assert.strictEqual(stats.byType.phone, 1);
      });

      it('should throw on unknown pattern', () => {
        assert.throws(
          () => redact('test', { include: ['unknownPattern'] }),
          /Unknown patterns: unknownPattern/,
        );
      });
    });
  });

  describe('detect()', () => {
    it('should detect sensitive data', () => {
      const input = 'Email: test@example.com';
      const result = detect(input);

      assert.strictEqual(result.hasSensitiveData, true);
      assert.strictEqual(result.total, 1);
      assert.ok(result.matches.email);
      assert.strictEqual(result.matches.email.count, 1);
    });

    it('should detect multiple types', () => {
      const input = 'test@example.com 555-123-4567 192.168.1.1';
      const result = detect(input);

      assert.strictEqual(result.hasSensitiveData, true);
      assert.strictEqual(result.total, 3);
      assert.ok(result.matches.email);
      assert.ok(result.matches.phone);
      assert.ok(result.matches.ipv4);
    });

    it('should return false when no sensitive data', () => {
      const input = 'Just plain text here';
      const result = detect(input);

      assert.strictEqual(result.hasSensitiveData, false);
      assert.strictEqual(result.total, 0);
      assert.deepStrictEqual(result.matches, {});
    });

    it('should respect options', () => {
      const input = 'Email: test@example.com, Phone: 555-123-4567';
      const result = detect(input, { include: ['email'] });

      assert.strictEqual(result.total, 1);
      assert.ok(result.matches.email);
      assert.ok(!result.matches.phone);
    });

    it('should include partial samples', () => {
      const input = 'Email: verylongemail@example.com';
      const result = detect(input);

      assert.ok(result.matches.email.samples.length > 0);
      // Should be truncated
      assert.ok(result.matches.email.samples[0].includes('...'));
    });

    it('should throw on non-string input', () => {
      assert.throws(() => detect(null), /Input must be a string/);
    });
  });

  describe('listPatterns()', () => {
    it('should return all patterns', () => {
      const patterns = listPatterns();

      assert.ok(patterns.email);
      assert.ok(patterns.phone);
      assert.ok(patterns.creditCard);
      assert.ok(patterns.ssn);
    });

    it('should include descriptions', () => {
      const patterns = listPatterns();

      assert.strictEqual(typeof patterns.email.description, 'string');
      assert.ok(patterns.email.description.length > 0);
    });

    it('should indicate default status', () => {
      const patterns = listPatterns();

      assert.strictEqual(patterns.email.isDefault, true);
      assert.strictEqual(patterns.ipv6.isDefault, false);
    });
  });

  describe('exports', () => {
    it('should export defaultPatterns', () => {
      assert.ok(Array.isArray(defaultPatterns));
      assert.ok(defaultPatterns.includes('email'));
    });

    it('should export allPatternNames', () => {
      assert.ok(Array.isArray(allPatternNames));
      assert.ok(allPatternNames.length >= defaultPatterns.length);
    });
  });
});

describe('patterns', () => {
  describe('edge cases', () => {
    it('should handle mixed case emails', () => {
      const { text } = redact('Email: Test.User@EXAMPLE.COM');
      assert.strictEqual(text, 'Email: [EMAIL]');
    });

    it('should handle subdomains in emails', () => {
      const { text } = redact('Email: user@mail.example.co.uk');
      assert.strictEqual(text, 'Email: [EMAIL]');
    });

    it('should not redact invalid IPs', () => {
      const input = 'Not an IP: 999.999.999.999';
      const { text } = redact(input);
      assert.strictEqual(text, input);
    });

    it('should handle edge IP values', () => {
      const { text } = redact('IP: 0.0.0.0 and 255.255.255.255');
      assert.strictEqual(text, 'IP: [IPv4] and [IPv4]');
    });

    it('should handle consecutive redactions', () => {
      const input = 'a@b.com c@d.com e@f.com';
      const { text } = redact(input);
      assert.strictEqual(text, '[EMAIL] [EMAIL] [EMAIL]');
    });

    it('should preserve line breaks', () => {
      const input = 'Line1: test@example.com\nLine2: 555-123-4567';
      const { text } = redact(input);
      assert.ok(text.includes('\n'));
      assert.strictEqual(text, 'Line1: [EMAIL]\nLine2: [PHONE]');
    });

    it('should handle unicode around PII', () => {
      const input = '📧 test@example.com 📞 555-123-4567';
      const { text } = redact(input);
      assert.strictEqual(text, '📧 [EMAIL] 📞 [PHONE]');
    });
  });
});
