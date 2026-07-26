import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
import {
  getNextVersion,
  getReleaseType,
  incrementVersion,
} from './release-utils.mjs'

test('does not release when there are no commits', () => {
  assert.equal(getReleaseType([]), null)
})

test('uses patch releases for fixes and non-conventional commits', () => {
  assert.equal(getReleaseType(['fix: repair archive validation']), 'patch')
  assert.equal(getReleaseType(['Polish the release documentation']), 'patch')
})

test('uses minor releases for features', () => {
  assert.equal(getReleaseType(['feat: add route selection']), 'minor')
})

test('uses major releases for breaking changes', () => {
  assert.equal(getReleaseType(['feat!: replace the launcher contract']), 'major')
  assert.equal(
    getReleaseType(['refactor: change config\n\nBREAKING CHANGE: routes require peers']),
    'major',
  )
})

test('increments semantic versions', () => {
  assert.equal(incrementVersion('1.2.3', 'patch'), '1.2.4')
  assert.equal(incrementVersion('1.2.3', 'minor'), '1.3.0')
  assert.equal(incrementVersion('1.2.3', 'major'), '2.0.0')
})

test('derives the next version from the latest tag', () => {
  assert.equal(
    getNextVersion({
      latestTag: 'v1.3.2',
      messages: ['fix: repair release packaging'],
    }),
    '1.3.3',
  )
})

test('trigger workflow creates a release and publishes every build asset', () => {
  const workflow = readFileSync(
    resolve('.github/workflows/trigger-release.yml'),
    'utf8',
  )

  assert.match(workflow, /workflow_dispatch:/)
  assert.match(workflow, /contents:\s+write/)
  assert.match(workflow, /OPENROUTER_API_KEY:\s+\$\{\{\s*secrets\.OPENROUTER_API_KEY\s*\}\}/)
  assert.match(workflow, /node scripts\/create-release\.mjs/)
  assert.match(workflow, /node scripts\/generate-release-notes\.mjs/)
  assert.match(workflow, /goos:\s+linux[\s\S]*?arch:\s+amd64/)
  assert.match(workflow, /goos:\s+linux[\s\S]*?arch:\s+arm64/)
  assert.match(workflow, /goos:\s+darwin[\s\S]*?arch:\s+amd64/)
  assert.match(workflow, /goos:\s+darwin[\s\S]*?arch:\s+arm64/)
  assert.match(workflow, /VERSION="\$TAG"/)
  assert.match(workflow, /gh release upload "\$TAG"/)
  assert.match(workflow, /gh release edit "\$TAG"/)
})

test('release creation targets the workflow commit', () => {
  const script = readFileSync(resolve('scripts/create-release.mjs'), 'utf8')

  assert.match(script, /target_commitish:\s+targetCommitish/)
  assert.match(script, /process\.env\.GITHUB_SHA/)
  assert.match(script, /setOutput\('no_release', 'true'\)/)
})

test('AI notes receive only bounded release context', () => {
  const script = readFileSync(
    resolve('scripts/generate-release-notes.mjs'),
    'utf8',
  )
  const prompt = readFileSync(
    resolve('.github/prompts/github-create-release.md'),
    'utf8',
  )

  assert.match(script, /getPreviousTag/)
  assert.match(script, /maximumDiffLength/)
  assert.match(script, /Git range:/)
  assert.match(script, /OPENROUTER_API_KEY/)
  assert.match(prompt, /only source of release changes/)
  assert.match(prompt, /experimental macOS support/)
})
