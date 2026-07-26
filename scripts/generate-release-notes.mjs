import { execFile } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'

const tag = process.argv[2]
const execFileAsync = promisify(execFile)
const maximumDiffLength = 60_000

if (!tag) {
  throw new Error('Missing release tag argument')
}

async function runGit(args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: process.cwd(),
    env: process.env,
    maxBuffer: 10 * 1024 * 1024,
  })

  return stdout.trim()
}

async function getPreviousTag(targetTag) {
  const stdout = await runGit(['tag', '--list', 'v*', '--sort=-version:refname'])
  const tags = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
  const tagIndex = tags.indexOf(targetTag)

  if (tagIndex === -1) {
    throw new Error(`Release tag ${targetTag} does not exist locally`)
  }

  return tags[tagIndex + 1] ?? null
}

async function getReleaseContext(targetTag) {
  const previousTag = await getPreviousTag(targetTag)
  const range = previousTag ? `${previousTag}..${targetTag}` : targetTag
  const emptyTree = previousTag
    ? null
    : await runGit(['hash-object', '-t', 'tree', '/dev/null'])
  const diffArguments = previousTag ? [range] : [emptyTree, targetTag]
  const [commits, changedFiles, diffStat, rawDiff] = await Promise.all([
    runGit(['log', '--reverse', '--format=%h %s%n%b', range]),
    runGit(['diff', '--name-only', ...diffArguments]),
    runGit(['diff', '--stat', ...diffArguments]),
    runGit(['diff', '--no-ext-diff', '--unified=1', ...diffArguments]),
  ])
  const diffWasTruncated = rawDiff.length > maximumDiffLength

  return {
    previousTag,
    range,
    commits: commits || '(no commits found)',
    changedFiles: changedFiles || '(no changed files found)',
    diffStat: diffStat || '(no diff stat available)',
    diff: diffWasTruncated
      ? `${rawDiff.slice(0, maximumDiffLength)}\n\n[diff truncated]`
      : rawDiff || '(no diff available)',
  }
}

function fallbackNotes(targetTag, context) {
  const bullets = context.commits
    .split('\n')
    .filter((line) => /^[0-9a-f]{7,}\s/.test(line))
    .map((line) => `- ${line}`)
    .join('\n')

  return [
    `WrapGuard ${targetTag} includes the changes completed since ${context.previousTag ?? 'the initial release'}.`,
    '',
    '## Changes',
    '',
    '### Included commits',
    '',
    bullets || '- Release maintenance and packaging updates.',
  ].join('\n')
}

function normalizeMarkdown(content) {
  return content
    .trim()
    .replace(/^```(?:markdown)?\s*/i, '')
    .replace(/\s*```$/, '')
    .trim()
}

async function generateAiNotes(targetTag, context) {
  const promptPath = resolve(
    process.cwd(),
    '.github/prompts/github-create-release.md',
  )
  const systemPrompt = await readFile(promptPath, 'utf8')
  const message = [
    `Generate the markdown changelog body for WrapGuard release ${targetTag}.`,
    `Only summarize changes in ${context.range}.`,
    context.previousTag
      ? `The previous release tag is ${context.previousTag}.`
      : 'There is no previous release tag.',
    'Do not include changes from earlier releases.',
    '',
    'Allowed release context:',
    '',
    `Target tag: ${targetTag}`,
    `Previous tag: ${context.previousTag ?? '(none)'}`,
    `Git range: ${context.range}`,
    '',
    'Commits in range:',
    context.commits,
    '',
    'Changed files in range:',
    context.changedFiles,
    '',
    'Diff stat:',
    context.diffStat,
    '',
    'Diff:',
    context.diff,
  ].join('\n')
  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': `https://github.com/${process.env.GITHUB_REPOSITORY ?? 'puzed/wrapguard'}`,
      'X-Title': 'WrapGuard release notes',
    },
    body: JSON.stringify({
      model: process.env.OPENROUTER_MODEL ?? 'anthropic/claude-haiku-4.5',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message },
      ],
      temperature: 0.2,
    }),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`OpenRouter request failed (${response.status}): ${error}`)
  }

  const result = await response.json()
  const content = result.choices?.[0]?.message?.content

  if (typeof content !== 'string' || !content.trim()) {
    throw new Error('OpenRouter returned empty release notes')
  }

  return normalizeMarkdown(content)
}

const releaseContext = await getReleaseContext(tag)
let notes = fallbackNotes(tag, releaseContext)

if (process.env.OPENROUTER_API_KEY) {
  try {
    notes = await generateAiNotes(tag, releaseContext)
  } catch (error) {
    console.warn(`${error.message}\nUsing commit-based release notes instead.`)
  }
} else {
  console.warn('OPENROUTER_API_KEY is not set; using commit-based release notes.')
}

await writeFile(resolve(process.cwd(), 'RELEASE.md'), `${notes}\n`)
