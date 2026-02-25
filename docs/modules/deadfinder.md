# Deadfinder

## Overview

BBOT integration for [Deadfinder](https://github.com/hahwul/deadfinder), an external Ruby utility for finding dead/broken links in web pages.

The `deadfinder` module triggers the `deadfinder pipe` mode against discovered `URL` events.

## Running

```bash
bbot -m deadfinder -t example.com
```

## Installation

Install Ruby + deadfinder dependencies with:

```bash
bbot -m deadfinder --force-deps
```

The Ruby package install is handled through BBOT's dependency installer and works across supported Linux families (Debian, Archlinux, RedHat, Alpine).

## Configuration

```yaml
modules:
  deadfinder:
    timeout: 10
    concurrency: 50
    include_30x: false
```

## Module Options

| Config Option             | Type | Description                                               | Default |
|--------------------------|------|-----------------------------------------------------------|---------|
| modules.deadfinder.version | str  | deadfinder gem version to install                          | 1.10.0  |
| modules.deadfinder.timeout | int  | per-request timeout in seconds                            | 10      |
| modules.deadfinder.concurrency | int | number of concurrent URL checks                         | 50      |
| modules.deadfinder.include_30x | bool | include 30x redirects as dead links or ignore   | False   |
| modules.deadfinder.dryrun | bool | only validate setup and skip scanning                       | false   |
