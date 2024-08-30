# Solana Validator Docs Readme

This validator's documentation is built using [Docusaurus v2](https://v2.docusaurus.io/) with `npm`.
Static content delivery is handled using `vercel`.

> Note: The documentation within this repo is specifically focused on the
> Solana validator client maintained by Solana Labs. The more "common"
> documentation, which is generalized to the Solana protocol as a whole and applies
> to all Solana validator implementations, is maintained within the
> [`developer-content`](https://github.com/solana-foundation/developer-content/)
> repo. Those "common docs" are managed by the Solana Foundation within their
> GitHub organization and are publicly accessible via
> [solana.com/docs](https://solana.com/docs)

## Local Development

To set up the Solana Validator Docs site locally:

- install dependencies using `npm`
- build locally via `./build.sh`
- run the local development server
- make your changes and updates as needed

> Note: After cloning this repo to your local machine, all the local development commands are run from within this `docs` directory.

### Install dependencies

Install the site's dependencies via `npm`:

```bash
npm install
```

### Build locally

The build script generates static content into the `build` directory and can be served using any static content hosting service.

```bash
./build.sh
```

Running this build script requires **Docker**, and will auto fetch the [solanalabs/rust](https://hub.docker.com/r/solanalabs/rust) image from Docker hub to compile the desired version of the [Solana CLI](https://docs.solanalabs.com/cli) from source.

This build script will also:

- generate the `cli/usage.md` document from the output of each of the Solana CLI commands and sub-commands
- convert each of the `art/*.bob` files into SVG images used throughout the docs
- generate the language [Translations](#translations)

> Note: Running this build script is **required** before being able to run the site locally via the `npm run start` command since it will generate the `cli/usage.md` document.

If you run into errors or issues with this step, see [Common Issues](#common-issues) below. See also [CI Build Flow](#ci-build-flow) for more details on production deployments of the docs.

### Local development server

This command starts the Docusaurus local development server and opens up a browser window.

```bash
npm run start
```

> Note: Most changes are reflected live without having to restart the server or refresh the page. However, some changes may require a manual refresh of the page or a restart of the development server (via the command above).

## Translations

Translations are sourced from [Crowdin](https://docusaurus.io/docs/i18n/crowdin)
and generated when the branch noted as the `STABLE` channel is built via the
`build.sh` script.

For local development, and with the `CROWDIN_PERSONAL_TOKEN` env variable set,
use the following two commands in this `docs` directory.

To download the newest documentation translations run:

```sh
npm run crowdin:download
```

To upload changes from `src` & generate
[explicit IDs](https://docusaurus.io/docs/markdown-features/headings#explicit-ids):

```shell
npm run crowdin:upload
```

> Translations are only included when deploying the `STABLE` channel of the docs
> (via `build.sh`). Resulting in only the `docs.solanalabs.com` documentation
> site to include translated content. Therefore, the `edge` and `beta` docs
> sites are not expected to include translated content, even though the language
> selector will still be present.

### Common issues

#### `CROWDIN_PERSONAL_TOKEN` env variable

The `crowdin.yml` file requires a `CROWDIN_PERSONAL_TOKEN` env variable to be
set with a valid Crowdin access token.

For local development, you can store this in a `.env` file that the Crowdin CLI
will auto detect.

For building and publishing via the GitHub actions, the `CROWDIN_PERSONAL_TOKEN`
secret must be set.

#### Translation locale fails to build with `SyntaxError`

Some translation locales may fail to build with a `SyntaxError` thrown by
Docusaurus due to how certain language symbols get parsed by Docusaurus while
generating the static version of the docs.

> Note: When any locale fails to build, the entire docs build will fail
> resulting in the docs not being able to be deployed at all.

There are several known locales that fail to build the current documentation.
They are listed in the commented out `localesNotBuilding` attribute in the
[`docusaurus.config.js`](https://github.com/solana-labs/solana/blob/master/docs/docusaurus.config.js)

## CI Build Flow

The docs are built and published in Github Actions with the `docs.yml` workflow. On each PR, the docs are built, but not published.

In each post-commit build, docs are built and published using `vercel` to their respective domain depending on the build branch.

- Master branch docs are published to `edge.docs.solanalabs.com`
- Beta branch docs are published to `beta.docs.solanalabs.com`
- Latest release tag docs are published to `docs.solanalabs.com`

## Common Issues

### Bad sidebars file (or `cli/usage` not found)

```bash
Error: Bad sidebars file.
These sidebar document ids do not exist:
- cli/usage,
```

If you have NOT successfully run the build script, then the `cli/usage.md` file will not exist within your local repo (since it is in `.gitignore`). Not having this doc file, will result in the error message above.

If the Rust toolchain (specifically `cargo`) is installed on your system, you can specifically build the `cli/usage.md` document via:

```bash
./build-cli-usage.sh
```

Or using Docker and the normal build script, you can perform a full production build of the docs to generate this file:

```bash
./build.sh
```

### Permission denied for the Docker socket

```bash
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post
```

Running docs build script (`./build.sh`) required the use of Docker.\*\*\*\*

Ensuring you have Docker installed on your system and it is running.

You may also try running either of these build scripts (and by association, Docker) with elevation permissions via `sudo`:

```bash
sudo ./build.sh
# or
sudo ./build-cli-usage.sh
```

### Multiple SVG images not found

```bash
Error: Image static/img/***.svg used in src/***.md not found.
```

During the build process of the docs (specifically within the `./convert-ascii-to-svg.sh` script run by `./build.sh`), each of the `art/*.bob` files are converted to SVG images and saved to the `static/img` directory.

To correct this issue, use the steps above to [build the docs locally](#build-locally).

> Note: While not generating and saving these SVG images within your local repo will **NOT** prevent you from running the local development server, it will result in numerous output errors in your terminal.
