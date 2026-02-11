/**
 * redakt - Text PII redaction engine
 * Zero-dependency module for detecting and masking sensitive data
 */

const { patterns, defaultPatterns, allPatternNames } = require('./patterns');

/**
 * Statistics tracking for redactions
 * @typedef {Object} RedactStats
 * @property {number} total - Total number of redactions
 * @property {Object.<string, number>} byType - Count by pattern type
 */

/**
 * Redaction options
 * @typedef {Object} RedactOptions
 * @property {string[]} [include] - Patterns to include (defaults to defaultPatterns)
 * @property {string[]} [exclude] - Patterns to exclude
 * @property {boolean} [all] - Include all patterns
 * @property {boolean} [stats] - Track and return statistics
 */

/**
 * Redaction result
 * @typedef {Object} RedactResult
 * @property {string} text - Redacted text
 * @property {RedactStats} [stats] - Statistics (if stats option is true)
 */

/**
 * Get active patterns based on options
 * @param {RedactOptions} options
 * @returns {string[]} Array of pattern names to use
 */
function getActivePatterns(options = {}) {
  let active;

  if (options.all) {
    active = [...allPatternNames];
  } else if (options.include && options.include.length > 0) {
    active = [...options.include];
  } else {
    active = [...defaultPatterns];
  }

  // Apply exclusions
  if (options.exclude && options.exclude.length > 0) {
    active = active.filter((p) => !options.exclude.includes(p));
  }

  // Validate pattern names
  const invalid = active.filter((p) => !patterns[p]);
  if (invalid.length > 0) {
    throw new Error(`Unknown patterns: ${invalid.join(', ')}`);
  }

  return active;
}

/**
 * Redact sensitive data from text
 * @param {string} text - Input text to redact
 * @param {RedactOptions} [options] - Redaction options
 * @returns {RedactResult} Redacted text and optional stats
 */
function redact(text, options = {}) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }

  const activePatterns = getActivePatterns(options);
  const stats = options.stats ? { total: 0, byType: {} } : null;

  let result = text;

  for (const patternName of activePatterns) {
    const pattern = patterns[patternName];
    // Clone regex to reset lastIndex
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

    let count = 0;
    result = result.replace(regex, (match, ...args) => {
      const replacement = pattern.replace(match, ...args);
      if (replacement !== match) {
        count++;
      }
      return replacement;
    });

    if (stats && count > 0) {
      stats.byType[patternName] = count;
      stats.total += count;
    }
  }

  if (stats) {
    return { text: result, stats };
  }

  return { text: result };
}

/**
 * Check if text contains any sensitive data
 * @param {string} text - Input text to check
 * @param {RedactOptions} [options] - Options
 * @returns {Object} Detection results with matches
 */
function detect(text, options = {}) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }

  const activePatterns = getActivePatterns(options);
  const results = {
    hasSensitiveData: false,
    matches: {},
    total: 0,
  };

  for (const patternName of activePatterns) {
    const pattern = patterns[patternName];
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    const matches = text.match(regex) || [];

    if (matches.length > 0) {
      results.hasSensitiveData = true;
      results.matches[patternName] = {
        count: matches.length,
        description: pattern.description,
        // Show partial matches for reference (first 3 chars only)
        samples: [...new Set(matches)]
          .slice(0, 3)
          .map((m) => (m.length > 6 ? `${m.slice(0, 3)}...${m.slice(-3)}` : '***')),
      };
      results.total += matches.length;
    }
  }

  return results;
}

/**
 * List available patterns
 * @returns {Object} Pattern info
 */
function listPatterns() {
  const info = {};
  for (const [name, pattern] of Object.entries(patterns)) {
    info[name] = {
      description: pattern.description,
      isDefault: defaultPatterns.includes(name),
    };
  }
  return info;
}

module.exports = {
  redact,
  detect,
  listPatterns,
  patterns,
  defaultPatterns,
  allPatternNames,
};
