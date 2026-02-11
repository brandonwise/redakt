import {
  baseRules,
  testRules,
  nodeGlobals,
  testGlobals,
  ignores,
} from '../_config/eslint.base.mjs';

export default [
  {
    ignores,
  },
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: nodeGlobals,
    },
    rules: baseRules,
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: testGlobals,
    },
    rules: testRules,
  },
];
