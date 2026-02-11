#!/usr/bin/env node

/**
 * redakt CLI - Detect and mask PII in text
 * Usage: redakt [options] [file]
 *        cat file.log | redakt
 */

const fs = require('fs');
const { redact, detect, listPatterns } = require('./redakt');

const VERSION = require('../package.json').version;

const HELP = `
redakt v${VERSION} - Detect and mask PII in text

USAGE:
  redakt [options] [file]      Process file
  cat file | redakt            Process stdin
  echo "text" | redakt         Process piped text

OPTIONS:
  -h, --help              Show this help
  -v, --version           Show version
  -l, --list              List available patterns
  -d, --detect            Detection mode (don't redact, just report)
  -s, --stats             Show redaction statistics
  -q, --quiet             Suppress status messages (output only)
  -a, --all               Enable all patterns (including extras)
  -i, --include <p,...>   Include only these patterns (comma-separated)
  -x, --exclude <p,...>   Exclude these patterns (comma-separated)
  -o, --output <file>     Write output to file (default: stdout)

PATTERNS:
  Default: email, phone, creditCard, ssn, ipv4, bearerToken, jwt,
           urlWithCreds, githubToken, slackToken, privateKey

  Extra:   ipv6, awsKey, awsSecret, hexSecret

EXAMPLES:
  # Redact a log file
  redakt server.log > sanitized.log

  # Pipe from clipboard (macOS)
  pbpaste | redakt | pbcopy

  # Detection mode - just report what was found
  redakt -d sensitive.txt

  # Include only specific patterns
  redakt -i email,phone data.txt

  # Exclude patterns
  redakt -x ipv4 --stats logs.txt

  # All patterns including extras
  redakt -a config.yml
`;

/**
 * Parse command line arguments
 */
function parseArgs(argv) {
  const args = {
    help: false,
    version: false,
    list: false,
    detect: false,
    stats: false,
    quiet: false,
    all: false,
    include: [],
    exclude: [],
    output: null,
    file: null,
  };

  let i = 2; // Skip node and script name
  while (i < argv.length) {
    const arg = argv[i];

    if (arg === '-h' || arg === '--help') {
      args.help = true;
    } else if (arg === '-v' || arg === '--version') {
      args.version = true;
    } else if (arg === '-l' || arg === '--list') {
      args.list = true;
    } else if (arg === '-d' || arg === '--detect') {
      args.detect = true;
    } else if (arg === '-s' || arg === '--stats') {
      args.stats = true;
    } else if (arg === '-q' || arg === '--quiet') {
      args.quiet = true;
    } else if (arg === '-a' || arg === '--all') {
      args.all = true;
    } else if (arg === '-i' || arg === '--include') {
      i++;
      if (argv[i]) {
        args.include = argv[i].split(',').map((p) => p.trim());
      }
    } else if (arg === '-x' || arg === '--exclude') {
      i++;
      if (argv[i]) {
        args.exclude = argv[i].split(',').map((p) => p.trim());
      }
    } else if (arg === '-o' || arg === '--output') {
      i++;
      args.output = argv[i];
    } else if (!arg.startsWith('-') && !args.file) {
      args.file = arg;
    }

    i++;
  }

  return args;
}

/**
 * Read input from file or stdin
 */
async function readInput(filePath) {
  if (filePath) {
    if (!fs.existsSync(filePath)) {
      console.error(`Error: File not found: ${filePath}`);
      process.exit(1);
    }
    return fs.readFileSync(filePath, 'utf8');
  }

  // Read from stdin
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');

    if (process.stdin.isTTY) {
      // No piped input and no file - show help
      console.log(HELP);
      process.exit(0);
    }

    process.stdin.on('data', (chunk) => {
      data += chunk;
    });

    process.stdin.on('end', () => {
      resolve(data);
    });
  });
}

/**
 * Format detection results for display
 */
function formatDetectionResults(results) {
  if (!results.hasSensitiveData) {
    return '✅ No sensitive data detected';
  }

  let output = `⚠️  Found ${results.total} sensitive item(s):\n`;

  for (const [pattern, info] of Object.entries(results.matches)) {
    output += `\n  ${pattern} (${info.count})\n`;
    output += `    ${info.description}\n`;
    if (info.samples.length > 0) {
      output += `    Samples: ${info.samples.join(', ')}\n`;
    }
  }

  return output;
}

/**
 * Format stats for display
 */
function formatStats(stats) {
  if (stats.total === 0) {
    return '✅ No redactions needed';
  }

  let output = `\n📊 Redacted ${stats.total} item(s):\n`;

  for (const [pattern, count] of Object.entries(stats.byType)) {
    output += `   ${pattern}: ${count}\n`;
  }

  return output;
}

/**
 * Main entry point
 */
async function main() {
  const args = parseArgs(process.argv);

  // Handle immediate actions
  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (args.version) {
    console.log(VERSION);
    process.exit(0);
  }

  if (args.list) {
    console.log('\nAvailable patterns:\n');
    const patterns = listPatterns();
    for (const [name, info] of Object.entries(patterns)) {
      const def = info.isDefault ? ' (default)' : '';
      console.log(`  ${name}${def}`);
      console.log(`    ${info.description}\n`);
    }
    process.exit(0);
  }

  // Build options
  const options = {
    all: args.all,
    include: args.include.length > 0 ? args.include : undefined,
    exclude: args.exclude.length > 0 ? args.exclude : undefined,
    stats: args.stats,
  };

  // Read input
  let input;
  try {
    input = await readInput(args.file);
  } catch (err) {
    console.error(`Error reading input: ${err.message}`);
    process.exit(1);
  }

  // Process
  try {
    if (args.detect) {
      // Detection mode
      const results = detect(input, options);
      console.log(formatDetectionResults(results));
      process.exit(results.hasSensitiveData ? 1 : 0);
    } else {
      // Redaction mode
      const result = redact(input, options);

      // Output redacted text
      if (args.output) {
        fs.writeFileSync(args.output, result.text);
        if (!args.quiet) {
          console.error(`✅ Written to ${args.output}`);
        }
      } else {
        process.stdout.write(result.text);
      }

      // Show stats if requested
      if (args.stats && !args.quiet) {
        console.error(formatStats(result.stats));
      }
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

// Run if invoked directly
if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { parseArgs, main };
