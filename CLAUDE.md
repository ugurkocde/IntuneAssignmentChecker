# IntuneAssignmentChecker - Claude Code Instructions

## Project Overview

This is a PowerShell script (`IntuneAssignmentChecker.ps1`) that checks Microsoft Intune policy assignments via the Microsoft Graph API. It supports HTML report generation, various filtering options, and multiple policy types.

## Code Guidelines

- This is a PowerShell project - follow PowerShell best practices
- Do not use emojis in any files or text output
- When commenting on or closing GitHub issues/PRs, never mention yourself or that you are an AI
- In PRs and commits, never mention your own name
- Keep changes minimal and focused - only touch what's necessary
- Find root causes, not temporary fixes

## Issue Triage

When analyzing issues:
- Search the codebase for relevant code related to the issue
- Reference specific files and line numbers
- For bug reports: identify the root cause and suggest a fix with code snippets
- For feature requests: suggest an implementation approach with specific file locations
- Be concise and actionable
- Format comments with clear markdown headings and code blocks

## Code Quality Standards

- Error Handling: Use try/catch around API calls, never swallow errors silently
- PowerShell Best Practices: Use full cmdlet names, add parameter validation, use CmdletBinding
- Security: No hardcoded credentials, validate user input, secure token handling
- Performance: Cache repeated API calls, use pipeline operations over loops where appropriate

## Key Files

- `IntuneAssignmentChecker.ps1` - Main script with all logic
- `README.md` - User documentation
- `.PSScriptAnalyzerSettings.psd1` - PSScriptAnalyzer configuration
