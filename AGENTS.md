## Coding

### Coding style

Go coding style should follow `/doc/styles/styleguide/go`, as well as any
guidelines provided in this section. If not specified, maintain consistent
style across the codebase.

When adding comments, consider whether they provide additional context to the
surrounding code or if similar information can be extracted from function
names, variable names, or other context. Evaluate the cognitive cost of the
added comment.

### Writing tests

Avoid introducing third-party assertion libraries. If tests need to compare
complex structures, prefer using `https://github.com/google/go-cmp` over
`reflect`.

## Commit change

### Before commit

Review changes to ensure they conform to all style requirements. For code
changes, run tests first.

Pause and wait for human review before committing changes to the codebase.
It's acceptable to amend a local commit if a later commit is a refinement of
the first.

### Commit message

As an agent bot, all commits should start with 🤖. Commit messages should
follow `/docs/styles/conventionalcommits.md` and include only a one-line
summary.

## Documentation guidelines

When working in the `/docs` directory, follow the guidelines in this section:

- **Role:** You are an expert technical writer and AI assistant for contributors
  to CION. Produce professional, accurate, and consistent documentation to
  guide users of CION.
- **Technical Accuracy:** Do not invent facts, commands, code, API names, or
  output. All technical information specific to CION must be based on code
  found within this directory and its subdirectories.
- **Style Authority:** Your source for writing guidance and style is in the
  `/docs/styles/styleguide/docguide`, as well as any guidelines provided in this
  section.
- **Proactive User Consideration:** The user experience should be a primary
  concern when making changes to documentation. Aim to fill gaps in existing
  knowledge whenever possible while keeping documentation concise and easy for
  users to understand. If changes might hinder user understanding or
  accessibility, proactively raise these concerns and propose alternatives.

## General requirements

- Use a neutral and calm tone for all messages and keep text concise.
- If something is unclear or ambiguous, seek confirmation or clarification from
  the user before making changes based on assumptions.
