const { describe, it } = require('node:test');
const assert = require('node:assert');
const { parseArgs } = require('../src/cli');

describe('CLI', () => {
  describe('parseArgs()', () => {
    it('should parse --help flag', () => {
      const args = parseArgs(['node', 'redakt', '--help']);
      assert.strictEqual(args.help, true);
    });

    it('should parse -h flag', () => {
      const args = parseArgs(['node', 'redakt', '-h']);
      assert.strictEqual(args.help, true);
    });

    it('should parse --version flag', () => {
      const args = parseArgs(['node', 'redakt', '--version']);
      assert.strictEqual(args.version, true);
    });

    it('should parse -v flag', () => {
      const args = parseArgs(['node', 'redakt', '-v']);
      assert.strictEqual(args.version, true);
    });

    it('should parse --list flag', () => {
      const args = parseArgs(['node', 'redakt', '--list']);
      assert.strictEqual(args.list, true);
    });

    it('should parse -l flag', () => {
      const args = parseArgs(['node', 'redakt', '-l']);
      assert.strictEqual(args.list, true);
    });

    it('should parse --detect flag', () => {
      const args = parseArgs(['node', 'redakt', '--detect']);
      assert.strictEqual(args.detect, true);
    });

    it('should parse -d flag', () => {
      const args = parseArgs(['node', 'redakt', '-d']);
      assert.strictEqual(args.detect, true);
    });

    it('should parse --stats flag', () => {
      const args = parseArgs(['node', 'redakt', '--stats']);
      assert.strictEqual(args.stats, true);
    });

    it('should parse -s flag', () => {
      const args = parseArgs(['node', 'redakt', '-s']);
      assert.strictEqual(args.stats, true);
    });

    it('should parse --quiet flag', () => {
      const args = parseArgs(['node', 'redakt', '--quiet']);
      assert.strictEqual(args.quiet, true);
    });

    it('should parse -q flag', () => {
      const args = parseArgs(['node', 'redakt', '-q']);
      assert.strictEqual(args.quiet, true);
    });

    it('should parse --all flag', () => {
      const args = parseArgs(['node', 'redakt', '--all']);
      assert.strictEqual(args.all, true);
    });

    it('should parse -a flag', () => {
      const args = parseArgs(['node', 'redakt', '-a']);
      assert.strictEqual(args.all, true);
    });

    it('should parse --include with comma-separated values', () => {
      const args = parseArgs(['node', 'redakt', '--include', 'email,phone,ssn']);
      assert.deepStrictEqual(args.include, ['email', 'phone', 'ssn']);
    });

    it('should parse -i with comma-separated values', () => {
      const args = parseArgs(['node', 'redakt', '-i', 'email,phone']);
      assert.deepStrictEqual(args.include, ['email', 'phone']);
    });

    it('should parse --exclude with comma-separated values', () => {
      const args = parseArgs(['node', 'redakt', '--exclude', 'ipv4,ipv6']);
      assert.deepStrictEqual(args.exclude, ['ipv4', 'ipv6']);
    });

    it('should parse -x with comma-separated values', () => {
      const args = parseArgs(['node', 'redakt', '-x', 'creditCard']);
      assert.deepStrictEqual(args.exclude, ['creditCard']);
    });

    it('should parse --output with file path', () => {
      const args = parseArgs(['node', 'redakt', '--output', 'out.txt']);
      assert.strictEqual(args.output, 'out.txt');
    });

    it('should parse -o with file path', () => {
      const args = parseArgs(['node', 'redakt', '-o', 'output.log']);
      assert.strictEqual(args.output, 'output.log');
    });

    it('should parse file argument', () => {
      const args = parseArgs(['node', 'redakt', 'input.txt']);
      assert.strictEqual(args.file, 'input.txt');
    });

    it('should parse multiple flags together', () => {
      const args = parseArgs([
        'node',
        'redakt',
        '-s',
        '-q',
        '-i',
        'email,phone',
        '-o',
        'out.txt',
        'input.log',
      ]);
      assert.strictEqual(args.stats, true);
      assert.strictEqual(args.quiet, true);
      assert.deepStrictEqual(args.include, ['email', 'phone']);
      assert.strictEqual(args.output, 'out.txt');
      assert.strictEqual(args.file, 'input.log');
    });

    it('should handle missing value after -i', () => {
      const args = parseArgs(['node', 'redakt', '-i']);
      assert.deepStrictEqual(args.include, []);
    });

    it('should handle missing value after -o', () => {
      const args = parseArgs(['node', 'redakt', '-o']);
      assert.strictEqual(args.output, undefined);
    });

    it('should return defaults when no args', () => {
      const args = parseArgs(['node', 'redakt']);
      assert.strictEqual(args.help, false);
      assert.strictEqual(args.version, false);
      assert.strictEqual(args.detect, false);
      assert.strictEqual(args.stats, false);
      assert.strictEqual(args.quiet, false);
      assert.strictEqual(args.all, false);
      assert.deepStrictEqual(args.include, []);
      assert.deepStrictEqual(args.exclude, []);
      assert.strictEqual(args.output, null);
      assert.strictEqual(args.file, null);
    });

    it('should trim whitespace from include values', () => {
      const args = parseArgs(['node', 'redakt', '-i', 'email , phone , ssn']);
      assert.deepStrictEqual(args.include, ['email', 'phone', 'ssn']);
    });
  });
});
