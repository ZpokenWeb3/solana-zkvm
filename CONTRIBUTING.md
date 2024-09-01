Thank you for your interest in contributing to the Solana community! We welcome contributions from all members, and we've provided some helpful information below to help you get started.

There are three primary ways to contribute:

* **Opening an Issue**: If you believe you have discovered a bug in project, report it by creating a new issue in the issue tracker.
* **Adding Context**: Enhance existing issues by providing additional information, such as screenshots or code snippets, to help with problem resolution.
* **Resolving Issues**: Contribute by demonstrating that a reported issue is not a problem or, more commonly, by submitting a pull request with a concrete and reviewable fix for the issue.

### Pull Requests
Please follow the following steps when creating a PR:
1. Fork the solana-zkvm repository and create a new branch there to do your work.
2. The branch can contain any number of commits. When merged, all commits will be squashed into a single commit.
3. The changes should be thoroughly tested.
4. When ready, send a pull request against the `main` branch of the repository.
5. Feel free to submit draft PRs to get early feedback and to make sure you are on the right track.
6. The PR name should follow the template: `<type>: <name>`. Where type is:
   - `fix` for bug fixes;
   - `feat` for new features;
   - `refactor` for changes that reorganize code without adding new content;
   - `doc` for changes that change documentation or comments;
   - `test` for changes that introduce new tests;
   - `chore` for grunt tasks like updating dependencies.
7. The PR should also contain a description when appropriate to provide additional information to help the reviewer inspect the proposed change.

### Submitting a bug report
The most important pieces of information we need in a bug report are:

* The platform you are on

* Code snippets if this is happening in relation to testing or building code

* Concrete steps to reproduce the bug

* Solana CLI and Risc zero toolchain version you are on

In order to rule out the possibility of the bug being in your project, the code snippets should be as minimal as possible. It is better if you can reproduce the bug with a small snippet as opposed to an entire project!

### Adding tests

If your proposed changes modify the code, whether by adding new features or fixing existing issues, the pull request should include one or more tests to ensure that project remains stable and does not regress in the future.
Types of tests include:

* **Unit tests**: These are ideal for testing functions that perform specific tasks and should cover individual components of the code.
* **Integration tests**: For general purpose, far-reaching functionality, integration tests should be added. The best way to add a new integration test is to look at existing ones and follow the style.

### Code of Conduct

This project follows [the Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct), which outlines the minimum standards of behavior expected from all contributors.

### Contributions Related to Spelling and Grammar

Currently, we are not accepting contributions that solely address spelling or grammatical corrections in documentation, code, or other areas.