# VANTA

**Vulnerability & Attack-surface Network Threat Analyzer**

VANTA is a Python-based security auditing project designed to collect and report selected observations about a web target and its externally visible attack surface.

## Project status

VANTA 1.0 is an early-stage project. Findings should be treated as observations requiring manual verification, not as proof that a system is exploitable.

## Features

The current source tree contains modules for:

- DNS information and subdomain discovery
- HTTP responses and security headers
- Cookie attribute inspection
- TLS configuration inspection
- Port and service fingerprinting
- Technology identification
- Common administrative path checks
- Robots.txt and web asset discovery
- TXT and JSON report generation

The presence of a module does not guarantee that every check is comprehensive or that every result is accurate.

## Requirements

- Windows or another compatible Python environment
- Python 3.13 is the current development environment, but compatibility should be verified on other versions
- Tkinter for the graphical interface

The project currently uses Python standard-library imports in its inspected source files. Additional requirements, if any, must be confirmed before release.

## Run

From the project directory, run:

    python main.py

If Python is not available as `python` in your terminal, use the path to your Python executable or configure your development environment.

## Responsible use

- Scan only systems you own or have explicit permission to assess.
- Follow applicable laws, service terms, and testing scope.
- Avoid disruptive testing and respect rate limits.
- Verify findings manually before reporting or acting on them.
- Do not treat a scanner result as a confirmed vulnerability without sufficient evidence.

## Reports and privacy

Review generated reports before sharing them. They may contain target hostnames, addresses, server details, and other information that should not be made public without authorization.

## License

A license has not yet been selected. Until a license is added, do not assume that the project is available for unrestricted reuse, modification, or redistribution.
