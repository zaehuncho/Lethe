# Security Policy

## Supported versions

Until Lethe publishes tagged releases, only the current `main` branch receives
security fixes. Older commits, forks, and locally modified builds are not
supported.

## Reporting a vulnerability

Please use the repository's **Security** tab and select **Report a
vulnerability** to submit a private report. Do not disclose suspected
vulnerabilities in a public issue, pull request, discussion, or social-media
post. If private vulnerability reporting is not available, contact the
repository owner privately through their GitHub profile.

Include the affected commit, platform, impact, minimal reproduction steps,
relevant logs, and any suggested mitigation. Remove secrets and personal data
from attachments.

The maintainer aims to acknowledge a report within seven days, will coordinate
validation and remediation on a best-effort basis, and will credit reporters
who request attribution. Please allow a reasonable remediation window before
public disclosure. This project does not currently operate a bug-bounty
program.

In scope are vulnerabilities in Lethe's packer, native stub, bootstrap,
cryptographic use, release process, and dependency or build pipeline. Testing
unrelated third-party systems or software without the owner's authorization is
out of scope.
