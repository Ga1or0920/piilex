# GitHub Discussions Setup

## Enable Discussions

1. Go to repository Settings > General
2. Scroll to Features section
3. Check "Discussions"

## Categories

Configure these categories in Settings > Discussions > Categories:

| Emoji | Category | Description | Format |
|-------|----------|-------------|--------|
| Q | Q&A | Ask questions and get answers | Question/Answer |
| Idea | Ideas | Feature ideas and brainstorming | Open |
| Show | Show and Tell | Share how you use piilex | Open |
| Chat | General | General discussion | Open |
| Mega | Announcements | Release notes and updates (maintainers only) | Announcement |

## Pinned Discussions

Create and pin these after setup:

### 1. Welcome
```
Title: Welcome to piilex Discussions!
Category: General

Welcome! This is the place to ask questions, share ideas, and discuss piilex.

Quick links:
- [README](https://github.com/piilex/piilex#readme)
- [Install](https://github.com/piilex/piilex#install)
- [Bug Reports](https://github.com/piilex/piilex/issues/new?template=bug_report.yml)
- [Discord](https://discord.gg/piilex)

Guidelines:
- Use Q&A for questions
- Use Ideas for feature requests
- Use GitHub Issues for formal bug reports
```

### 2. FAQ
```
Title: Frequently Asked Questions
Category: Q&A

**Q: How do I install piilex?**
brew install piilex/tap/piilex
or: npm install -g piilex

**Q: Which languages are supported?**
TypeScript, JavaScript, Python, Go, Java, C#

**Q: What's the difference between Free and Pro?**
Free: PII detection, data flow, JSON/SARIF output
Pro: Regulatory mapping (GDPR/CCPA/APPI), reports, baseline diff, unlimited suggestions

**Q: How do I activate Pro?**
piilex license activate <JWT_TOKEN>
or set PIILEX_LICENSE_KEY environment variable

**Q: Is my code sent to any server?**
No. piilex runs entirely locally. No code leaves your machine.
```
