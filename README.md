
# 📦 python-tool

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
![Python version: 3.12+](https://img.shields.io/badge/python-3.12+-blue)
[![Common Changelog](https://common-changelog.org/badge.svg)](https://common-changelog.org)


## Overview

This project is a template for creating Python packages that follows the guidelines contained in [PEP 621](https://peps.python.org/pep-0621).
It uses a `pyproject.toml` file to store build system requirements and package information.


## Structure

- `.github/worflows` contains GitHub actions used for building, testing, and publishing.
- `docs` contains the package documentation, generated using Sphinx.
- `src` contains the source code of the package.
- `tests` contains pytest unit tests.

## Installation

Install the package locally with `pip install`:

```bash
$ pip install .
```


## Usage

This package offers a basic CLI to play around with.
It can be launched by running:

```bash
$ python -m tool
```

Or by invoking the `tool` [console script](https://setuptools.pypa.io/en/latest/userguide/entry_point.html#console-scripts).


## Documentation

- [Official Documentation](https://x55xaa.github.io/python-tool)
- [CHANGELOG](https://github.com/x55xaa/python-tool/blob/main/CHANGELOG.md)
