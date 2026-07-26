Write a polished GitHub release changelog for WrapGuard from the supplied release context.

Rules:
- Treat the supplied previous-tag-to-target-tag git range as the only source of release changes.
- Do not claim that final-state project files prove a feature was introduced in this release.
- Do not include changes that were already present in earlier releases.
- Focus on user-visible routing behavior, platform support, reliability, packaging, and contributor workflow.
- Be precise about experimental macOS support and do not overstate compatibility.
- Do not include front matter, metadata, a title, or a leading `---`.
- Do not attempt to publish a release.
- Return only the markdown changelog body.
- Start with a short, polished introductory sentence.
- Use two to four `##` sections, each containing at least one `###` subheading.
- Prefer concise, specific bullet lists written in the past tense.
- Synthesize meaningful changes instead of repeating the commit log.
