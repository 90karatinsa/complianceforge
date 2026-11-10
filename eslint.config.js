// SPDX-License-Identifier: MIT

import js from '@eslint/js';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import prettier from 'eslint-config-prettier';
import importPlugin from 'eslint-plugin-import';
import globals from 'globals';

const tsconfigRootDir = new URL('.', import.meta.url).pathname;

export default [
  {
    ignores: ['dist/**', 'api/dist/**', 'worker/dist/**']
  },
  {
    files: ['**/*.ts'],
    ignores: ['node_modules/**'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: ['./tsconfig.eslint.json'],
        tsconfigRootDir,
        ecmaVersion: 'latest',
        sourceType: 'module'
      },
      globals: {
        ...globals.node
      }
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      import: importPlugin
    },
    settings: {
      'import/resolver': {
        typescript: {
          project: './tsconfig.eslint.json'
        },
        node: {
          extensions: ['.ts', '.js']
        }
      },
      'import/core-modules': ['vitest/config', 'keytar', 'undici', 'jsdom']
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tsPlugin.configs['recommended-type-checked'].rules,
      ...prettier.rules,
      'import/no-unresolved': 'error'
    }
  }
];
