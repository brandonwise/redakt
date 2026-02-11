/**
 * redakt - Detect and mask PII in text
 *
 * Zero-dependency module for detecting and redacting sensitive data
 * including emails, phone numbers, credit cards, API keys, and more.
 *
 * @example
 * const { redact, detect } = require('redakt');
 *
 * // Redact all PII
 * const result = redact('Contact me at john@example.com');
 * console.log(result.text); // "Contact me at [EMAIL]"
 *
 * // With statistics
 * const result = redact(text, { stats: true });
 * console.log(result.stats); // { total: 3, byType: { email: 1, phone: 2 } }
 *
 * // Detection only
 * const info = detect(text);
 * if (info.hasSensitiveData) {
 *   console.log('Found sensitive data:', info.matches);
 * }
 */

const {
  redact,
  detect,
  listPatterns,
  patterns,
  defaultPatterns,
  allPatternNames,
} = require('./redakt');

module.exports = {
  redact,
  detect,
  listPatterns,
  patterns,
  defaultPatterns,
  allPatternNames,
};
