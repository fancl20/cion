# Use Markdown Architectural Decision Records

*   Status: accepted
*   Date: 2025-12-10

## Context and Problem Statement

We want to record architectural decisions, but we do not have a standard way to
do so yet.

## Decision Drivers

*   We need a way to track architectural decisions in the repository.
*   The format should be lightweight and easy to read.
*   It should be version-controlled alongside the code.

## Considered Options

*   Wiki pages
*   Google Docs
*   Markdown Architectural Decision Records (MADR)

## Decision Outcome

Chosen option: "Markdown Architectural Decision Records (MADR)", because it
meets all our requirements for a lightweight, version-controlled decision log
that lives with the code.

### Positive Consequences

*   Decisions are versioned with the code.
*   Easy to read and write (Markdown).
*   No external tools required.

### Negative Consequences

*   Requires discipline to keep updated.

## Pros and Cons of the Options

### Wiki pages

*   Good, because easy to edit.
*   Bad, because separate from code history.

### Google Docs

*   Good, because of collaboration features.
*   Bad, because not versioned with code and harder to discover for developers
    working in the repo.

### Markdown Architectural Decision Records (MADR)

*   Good, because it is text-based and works well with git.
*   Good, because it uses a standard, recognizable format.
