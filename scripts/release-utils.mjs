const BREAKING_CHANGE_PATTERN = /(^|\n)BREAKING CHANGE:/m
const CONVENTIONAL_COMMIT_PATTERN =
  /^(?<type>[a-z]+)(\([^)]+\))?(?<breaking>!)?:\s.+$/i

function parseVersion(version) {
  const match = /^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$/.exec(version)

  if (!match?.groups) {
    throw new Error(`Invalid semantic version: ${version}`)
  }

  return {
    major: Number(match.groups.major),
    minor: Number(match.groups.minor),
    patch: Number(match.groups.patch),
  }
}

export function incrementVersion(version, releaseType) {
  const parsed = parseVersion(version)

  if (releaseType === 'major') {
    return `${parsed.major + 1}.0.0`
  }

  if (releaseType === 'minor') {
    return `${parsed.major}.${parsed.minor + 1}.0`
  }

  if (releaseType === 'patch') {
    return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`
  }

  throw new Error(`Unsupported release type: ${releaseType}`)
}

export function getReleaseType(messages) {
  if (messages.length === 0) {
    return null
  }

  let releaseType = 'patch'

  for (const message of messages) {
    if (BREAKING_CHANGE_PATTERN.test(message)) {
      return 'major'
    }

    const firstLine = message.split('\n', 1)[0]
    const conventionalMatch = CONVENTIONAL_COMMIT_PATTERN.exec(firstLine)

    if (!conventionalMatch?.groups) {
      continue
    }

    if (conventionalMatch.groups.breaking) {
      return 'major'
    }

    if (conventionalMatch.groups.type.toLowerCase() === 'feat') {
      releaseType = 'minor'
    }
  }

  return releaseType
}

export function getNextVersion({ latestTag, messages }) {
  const releaseType = getReleaseType(messages)

  if (!releaseType) {
    return null
  }

  const currentVersion = latestTag ? latestTag.replace(/^v/, '') : '0.0.0'
  return incrementVersion(currentVersion, releaseType)
}
