[SSTImap](https://github.com/vladko312/sstimap) Extra Plugins
======
[![SSTImap 1.3](https://img.shields.io/badge/SSTImap-1.3-green.svg?logo=github)](https://github.com/vladko312/sstimap)
[![Payload count](https://img.shields.io/badge/Plugins-6-green.svg?logo=github)](https://github.com/vladko312/extras)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg?logo=python)](https://www.python.org/downloads/release/python-3130/)
[![Python 3.6](https://img.shields.io/badge/python-3.6+-yellow.svg?logo=python)](https://www.python.org/downloads/release/python-360/)
[![GitHub](https://img.shields.io/github/license/vladko312/extras?color=green&logo=gnu)](https://www.gnu.org/licenses/gpl-3.0.txt)
[![GitHub last commit](https://img.shields.io/github/last-commit/vladko312/extras?color=green&logo=github)](https://github.com/vladko312/extras/commits/)
[![Maintenance](https://img.shields.io/maintenance/yes/2025?logo=github)](https://github.com/vladko312/extras)

This repository contains SSTImap plugins, which might be useful in some specific cases, but are too situational to include in the main repository.

## Installation:
- Install the latest version of SSTImap.
- Clone this repository inside `plugins/` directory of SSTImap.
> Alternatively, required plugins can be manually saved in `plugins/custom/` directory of SSTImap.

## List of supported plugins
| Plugin                                                                             | Ver.  | RCE | Tech | Code evaluation | Type |
|------------------------------------------------------------------------------------|-------|-----|------|-----------------|------|
| [CVE_2025_1302](https://gist.github.com/nickcopi/11ba3cb4fdee6f89e02e6afae8db6456) | 1.2.3 | ✓   | REBT | JavaScript      | CVE  |
| [CVE-2025-13204](https://huntr.com/bounties/1-npm-expr-eval)                       | 1.2.3 | ✓   | REBT | JavaScript      | CVE  |
| [CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614)                  | 1.2.3 | ✓   | REBT | PHP             | CVE  |
| [CVE-2024-6386](https://sec.stealthcopter.com/wpml-rce-via-twig-ssti/)             | 1.2.3 | ✓   | REBT | PHP             | CVE  |
| Smarty_old                                                                         | 1.2.3 | ✓   | REBT | PHP             | old  |
| Jinja2_old                                                                         | 1.2.3 | ✓   | REBT | PHP             | old  |

Techniques: (R)endered, (E)rror-based, (B)oolean error-based blind and (T)ime-based blind; Lowercase letter marks partially supported technique

## Plugin details 
- **[CVE_2025_1302](https://gist.github.com/nickcopi/11ba3cb4fdee6f89e02e6afae8db6456)** - JSONPath Plus < 10.3.0 RCE via JavaScript eval

Plugin automates detection and exploitation of [CVE-2025-1302](https://nvd.nist.gov/vuln/detail/CVE-2025-1302) providing post-exploitation capabilities. This plugin can automatically detect many JSONpath injection contexts and more would be added in the future.

- **[CVE-2025-13204](https://huntr.com/bounties/1-npm-expr-eval)** - expr-eval <= 2.0.2 RCE via JavaScript eval

Plugin automates detection and exploitation of [CVE-2025-13204](https://nvd.nist.gov/vuln/detail/CVE-2025-13204) providing post-exploitation capabilities. Node.JS module `expr-eval` up to the latest version 2.0.2 is vulnerable to JavaScript eval injection.

- **[CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614)** - Sandbox bypass in Twig >=2.12 <2.14.11 and >=3.0 <3.3.8

Plugin automates detection and exploitation of [CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614), bypassing sandbox in Twig using |sort filter with PHP functions.
 
- **[CVE_2024_6386](https://sec.stealthcopter.com/wpml-rce-via-twig-ssti/)** - WPML Multilingual CMS Contributor+ RCE via Twig SSTI

Plugin automates detection and exploitation of [CVE-2024-6386](https://nvd.nist.gov/vuln/detail/CVE-2024-6386) providing post-exploitation capabilities. Correctly set headers `X-WP-Nonce` and `Content-Type` as well as cookies are required for exploitation. Example:
```bash
./sstimap.py -i -e CVE_2024_6386 --data-type json -m POST -H "Content-Type: application/json" -H "X-WP-Nonce: ..." -H "Cookie: ..." -d '{"id":...,"content":"*"}' -u "http://localhost/index.php?rest_route=%2Fwp%2Fv2%2Fpages%2F..."
```
 
- **Smarty_old** - Smarty template engine prior to version 3.0 using {php}{/php} tags
 
- **Jinja2_old** - Old long payloads for Jinja template engine

## Developing plugins
New plugins are always welcome in PRs

### Debugging tips
- Use `-e`/`--engine` option with the name of the plugin's class, e.g. `-e CVE_2024_6386` to use a specific plugin
- Use `-p`/`--proxy` option with BurpSuite or a similar tool to see the requests, e.g. `-p http://127.0.0.1:8080`
- Use interactive mode (`-i`/`--interactive`) to preserve settings between runs. Use `run` to run tests and `reload` to reload plugins from disk (e.g. after some changes)
- Use `--data-type fromhex` to provide request body as hex-encoded string with `*` as injection marker, if body format is not supported otherwise, e.g. `--data-type fromhex --data E29885C2AB*C2BBE29885`

#### Example
- Install the latest version of SSTImap
- Copy `CVE_2024_6386.py` plugin to `plugins/custom` inside SSTImap directory
- Run the following command:
```bash
./sstimap.py -i -e CVE_2024_6386 -p http://127.0.0.1:8080 --data-type json -m POST -H "Content-Type: application/json" -H "X-WP-Nonce: ..." -H "Cookie: ..." -d '{"id":...,"content":"*"}' -u "http://localhost/index.php?rest_route=%2Fwp%2Fv2%2Fpages%2F..."
```
- Use `run` command to test the payload
- Edit the payload, use commands `reload` and `run`
