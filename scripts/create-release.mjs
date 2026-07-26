import { execFile } from 'node:child_process'
import { appendFileSync } from 'node:fs'
import { promisify } from 'node:util'
import { getNextVersion } from './release-utils.mjs'

const execFileAsync = promisify(execFile)

async function run(command, args) {
  const { stdout } = await execFileAsync(command, args, {
    cwd: process.cwd(),
    env: process.env,
  })

  return stdout.trim()
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`)
  }
}

async function getLatestTag() {
  const stdout = await run('git', ['tag', '--list', 'v*', '--sort=-version:refname'])
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .find(Boolean) ?? null
}

async function getCommitMessages(latestTag) {
  const args = latestTag
    ? ['log', `${latestTag}..HEAD`, '--format=%B%x1e']
    : ['log', '--format=%B%x1e']
  const stdout = await run('git', args)

  return stdout
    .split('\x1e')
    .map((message) => message.trim())
    .filter(Boolean)
}

async function tagExists(tag) {
  try {
    await execFileAsync('git', ['rev-parse', '-q', '--verify', `refs/tags/${tag}`], {
      cwd: process.cwd(),
      env: process.env,
    })
    return true
  } catch {
    return false
  }
}

async function createGitHubRelease(tag, targetCommitish) {
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN
  const repository = process.env.GITHUB_REPOSITORY

  if (!token || !repository) {
    throw new Error('GITHUB_TOKEN and GITHUB_REPOSITORY are required')
  }

  const response = await fetch(`https://api.github.com/repos/${repository}/releases`, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'User-Agent': 'wrapguard-release-script',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      tag_name: tag,
      target_commitish: targetCommitish,
      name: tag,
      body: 'Release build in progress.',
      draft: false,
      prerelease: false,
      generate_release_notes: false,
    }),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to create GitHub release for ${tag}: ${error}`)
  }
}

const latestTag = await getLatestTag()
const commitMessages = await getCommitMessages(latestTag)
const nextVersion = getNextVersion({
  latestTag,
  messages: commitMessages,
})

if (!nextVersion) {
  setOutput('no_release', 'true')
  console.log('No release needed: HEAD has no commits after the latest release tag')
  process.exit(0)
}

const tag = `v${nextVersion}`

if (await tagExists(tag)) {
  throw new Error(`Release tag ${tag} already exists`)
}

const targetCommitish = process.env.GITHUB_SHA || await run('git', ['rev-parse', 'HEAD'])

await run('git', ['tag', tag, targetCommitish])

try {
  await createGitHubRelease(tag, targetCommitish)
} catch (error) {
  await run('git', ['tag', '--delete', tag])
  throw error
}

setOutput('tag', tag)
setOutput('no_release', 'false')
console.log(`Created GitHub release ${tag}`)
