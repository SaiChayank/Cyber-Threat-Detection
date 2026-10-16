// Run with: node --test scripts/verify-dependency-security.mjs
// Constructor-only cases exercise CVE-2026-93749 without amplifying offsets.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'

const require = createRequire(new URL('../frontend/package.json', import.meta.url))
const { SourceMapConsumer } = require('source-map-js')
const basic = { version: 3, sources: ['input.js'], names: [], mappings: 'AAAA' }
const indexed = (line, column = 0, map = basic) => ({
  version: 3,
  sections: [{ offset: { line, column }, map }],
})

test('indexed source maps reject an excessive section offset before serialization', () => {
  assert.throws(() => new SourceMapConsumer(indexed(1e12)))
})

test('indexed source maps also bound the combined offset of nested sections', () => {
  assert.throws(() => new SourceMapConsumer(indexed(6e6, 0, indexed(6e6))))
})

test('indexed source maps reject invalid numeric offset classes', () => {
  for (const [line, column] of [[-1, 0], [0.5, 0], [0, -1], [0, Infinity]]) {
    assert.throws(() => new SourceMapConsumer(indexed(line, column)))
  }
})

test('valid indexed source maps preserve usable source locations', () => {
  const consumer = new SourceMapConsumer(indexed(2))
  const mappings = []
  consumer.eachMapping((mapping) => mappings.push({
    source: mapping.source,
    generatedLine: mapping.generatedLine,
    originalLine: mapping.originalLine,
    originalColumn: mapping.originalColumn,
  }))
  assert.deepEqual(mappings, [{
    source: 'input.js', generatedLine: 3, originalLine: 1, originalColumn: 0,
  }])
})
