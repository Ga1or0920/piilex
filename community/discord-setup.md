# Discord Server Setup Guide

## Server Name
piilex

## Channel Structure

```
INFORMATION
  #welcome          Read-only. Server rules, links to docs/GitHub/pricing
  #announcements    Read-only. New releases, breaking changes

COMMUNITY
  #general          General discussion
  #help             Questions and troubleshooting
  #show-and-tell    Share how you use piilex

DEVELOPMENT
  #contributing     Discussion about contributing to piilex
  #feature-ideas    Feature requests and brainstorming
  #bug-reports      Quick bug discussions (formal reports on GitHub)

LANGUAGES
  #typescript-js    TypeScript and JavaScript specific
  #python           Python specific
  #go-java-csharp   Go, Java, C# specific

COMPLIANCE
  #gdpr             GDPR compliance discussion
  #ccpa             CCPA compliance discussion
  #appi             APPI (Japan) compliance discussion
```

## Roles

| Role | Color | Permissions |
|------|-------|-------------|
| @Admin | Red | Full admin |
| @Maintainer | Blue | Manage messages, pin, moderate |
| @Pro User | Green | Access to #pro-support (optional) |
| @Contributor | Purple | Badge for PR contributors |
| @everyone | Gray | Read and post in community channels |

## Permissions

### #welcome, #announcements
- @everyone: Read only
- @Admin, @Maintainer: Write

### Community channels
- @everyone: Read + Write
- Rate limit: 5 seconds slowmode on #general

### Development channels
- @everyone: Read + Write

## Welcome Message

```
Welcome to the piilex Discord!

piilex detects PII in source code and maps findings to GDPR, CCPA, and APPI.

Quick links:
  GitHub:   https://github.com/piilex/piilex
  Docs:     https://github.com/piilex/piilex#readme
  Install:  brew install piilex/tap/piilex
  Issues:   https://github.com/piilex/piilex/issues

Channels:
  #help         - Get help using piilex
  #feature-ideas - Suggest new features
  #bug-reports  - Discuss bugs (file formal reports on GitHub)

Rules:
  1. Be respectful
  2. No spam
  3. Use GitHub Issues for formal bug reports
  4. Keep discussions relevant to piilex and data privacy
```

## Bot Integration

### GitHub Bot
- Webhook: New releases -> #announcements
- Webhook: New issues -> #bug-reports (optional)

### Setup Steps
1. Create server at https://discord.com/
2. Create channels per structure above
3. Set permissions per role table
4. Add GitHub webhook to #announcements
5. Create invite link: https://discord.gg/piilex
6. Add link to README, website, and issue templates
