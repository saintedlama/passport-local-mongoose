# Contributing to passport-local-mongoose

Thank you for your interest in contributing to passport-local-mongoose! We welcome contributions from everyone.

## Getting Started

1. **Fork and Clone**
   - Fork the repository on GitHub.
   - Clone your fork locally:
     ```bash
     git clone https://github.com/saintedlama/passport-local-mongoose.git
     cd passport-local-mongoose
     ```

2. **Branching**
   - Create a feature branch off the default branch:
     ```bash
     git checkout -b feature/my-new-feature
     ```

## Making Changes

- Ensure all tests pass before submitting a pull request.
- Keep commits focused, well-documented, and follow [Conventional Commits](https://www.conventionalcommits.org/).
- If you're introducing a new feature, please include corresponding tests and documentation updates.

## Commit Message Guidelines

This project strictly follows the [Conventional Commits](https://www.conventionalcommits.org/) specification (`<type>(<scope>): <description>`). This enables automated changelogs and semantic releases.

Common types:
- `feat:` introduces a new feature
- `fix:` fixes a bug
- `docs:` documentation changes only
- `refactor:` code change that neither fixes a bug nor adds a feature
- `test:` adding or updating tests
- `chore:` maintenance, build tasks, dependency updates, or CI changes

Example:
```bash
git commit -m "feat(auth): add OAuth2 provider support"
git commit -m "fix(api): handle timeout when calling upstream service"
```

## Pull Request Guidelines

1. Push your changes to your fork:
   ```bash
   git push origin feature/my-new-feature
   ```
2. Open a Pull Request against the default branch of `saintedlama/passport-local-mongoose`.
3. Ensure PR titles also follow Conventional Commits (e.g. `feat: ...` or `fix: ...`).
4. Provide a clear and descriptive title and summary of the changes in the PR description.
5. Verify that CI checks and status checks pass.
6. Address any feedback during code review.

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Reporting Issues

If you find a bug or have a suggestion, please open an issue on GitHub. Before opening a new issue, please check if a similar issue already exists.
