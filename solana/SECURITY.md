# Security Policy

1. [Reporting security problems](#reporting)
4. [Security Bug Bounties](#bounty)
2. [Incident Response Process](#process)

<a name="reporting"></a>
## Reporting security problems in the Agave Validator

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Instead please use this [Report a Vulnerability](https://github.com/anza-xyz/agave/security/advisories/new) link.
Provide a helpful title, detailed description of the vulnerability and an exploit
proof-of-concept. Speculative submissions without proof-of-concept will be closed
with no further consideration.

Please refer to the
[Solana Program Library (SPL) security policy](https://github.com/solana-labs/solana-program-library/security/policy)
for vulnerabilities regarding SPL programs such as SPL Token.

If you haven't done so already, please **enable two-factor auth** in your GitHub account.

Expect a response as fast as possible in the advisory, typically within 72 hours.

--

If you do not receive a response in the advisory, send an email to
security@solana.com with the full URL of the advisory you have created.  DO NOT
include attachments or provide detail sufficient for exploitation regarding the
security issue in this email. **Only provide such details in the advisory**.

If you do not receive a response from security@solana.com please followup with
the team directly. You can do this in the `#core-technology` channel of the
[Solana Tech discord server](https://solana.com/discord), by pinging the `Anza`
role in the channel and referencing the fact that you submitted a security problem.

<a name="process"></a>
## Incident Response Process

In case an incident is discovered or reported, the following process will be
followed to contain, respond and remediate:

### 1. Accept the new report
In response a newly reported security problem, a member of the
`anza-xyz/admins` group will accept the report to turn it into a draft
advisory.  The `anza-xyz/security-incident-response` group should be added to
the draft security advisory, and create a private fork of the repository (grey
button towards the bottom of the page) if necessary.

If the advisory is the result of an audit finding, follow the same process as above but add the auditor's github user(s) and begin the title with "[Audit]".

If the report is out of scope, a member of the `anza-xyz/admins` group will
comment as such and then close the report.

### 2. Triage
Within the draft security advisory, discuss and determine the severity of the issue. If necessary, members of the anza-xyz/security-incident-response group may add other github users to the advisory to assist.
If it is determined that this is not a critical network issue then the advisory should be closed and if more follow-up is required a normal Solana public github issue should be created.

### 3. Prepare Fixes
For the affected branches, typically all three (edge, beta and stable), prepare a fix for the issue and push them to the corresponding branch in the private repository associated with the draft security advisory.
There is no CI available in the private repository so you must build from source and manually verify fixes.
Code review from the reporter is ideal, as well as from multiple members of the core development team.

### 4. Notify Security Group Validators
Once an ETA is available for the fix, a member of the anza-xyz/security-incident-response group should notify the validators so they can prepare for an update using the "Solana Red Alert" notification system.
The teams are all over the world and it's critical to provide actionable information at the right time. Don't be the person that wakes everybody up at 2am when a fix won't be available for hours.

### 5. Ship the patch
Once the fix is accepted it may be distributed directly to validators as a patch, depending on the vulnerability.

### 6. Public Disclosure and Release
Once the fix has been deployed to the security group validators, the patches from the security advisory may be merged into the main source repository. A new official release for each affected branch should be shipped and all validators requested to upgrade as quickly as possible.

### 7. Security Advisory Bounty Accounting and Cleanup
If this issue is [eligible](#eligibility) for a bounty, prefix the title of the
security advisory with one of the following, depending on the severity:
- [Bounty Category: Critical: Loss of Funds]
- [Bounty Category: Critical: Consensus / Safety Violations]
- [Bounty Category: Critical: Liveness / Loss of Availability]
- [Bounty Category: Critical: DoS Attacks]
- [Bounty Category: Supply Chain Attacks]
- [Bounty Category: RPC]

Confirm with the reporter that they agree with the severity assessment, and discuss as required to reach a conclusion.

We currently do not use the Github workflow to publish security advisories. Once the issue and fix have been disclosed, and a bounty category is assessed if appropriate, the GitHub security advisory is no longer needed and can be closed.

<a name="bounty"></a>
## Security Bug Bounties
At its sole discretion, the Solana Foundation may offer a bounty for
[valid reports](#reporting) of critical Solana vulnerabilities. Please see below
for more details. The submitter is not required to provide a
mitigation to qualify.

#### IMPORTANT | PLEASE NOTE
_Beginning February 1st 2024, the Security bounty program payouts will be updated in the following ways:_
- _Bug Bounty rewards will be denominated in SOL tokens, rather than USD value._
_This change is to better reflect for changing value of the Solana network._
- _Categories will now have a discretionary range to distinguish the varying severity_
_and impact of bugs reported within each broader category._

_Note: Payments will continue to be paid out in 12-month locked SOL._


#### Loss of Funds:
_Max: 25,000 SOL tokens. Min: 6,250 SOL tokens_

* Theft of funds without users signature from any account
* Theft of funds without users interaction in system, stake, vote programs
* Theft of funds that requires users signature - creating a vote program that drains the delegated stakes.

#### Consensus/Safety Violations:
_Max: 12,500 SOL tokens. Min: 3,125 SOL tokens_

* Consensus safety violation
* Tricking a validator to accept an optimistic confirmation or rooted slot without a double vote, etc.

#### Liveness / Loss of Availability:
_Max: 5,000 SOL tokens. Min: 1,250 SOL tokens_

* Whereby consensus halts and requires human intervention
* Eclipse attacks,
* Remote attacks that partition the network,

#### DoS Attacks:
_Max: 1,250 SOL tokens. Min: 315 SOL tokens_

* Remote resource exhaustion via Non-RPC protocols

#### Supply Chain Attacks:
_Max: 1,250 SOL tokens. Min: 315 SOL tokens_

* Non-social attacks against source code change management, automated testing, release build, release publication and release hosting infrastructure of the monorepo.

#### RPC DoS/Crashes:
_Max: 65 SOL tokens. Min: 20 SOL tokens_

* RPC attacks

### Out of Scope:
The following components are out of scope for the bounty program
* Metrics: `/metrics` in the monorepo as well as https://metrics.solana.com
* Any encrypted credentials, auth tokens, etc. checked into the repo
* Bugs in dependencies. Please take them upstream!
* Attacks that require social engineering
* Any undeveloped automated tooling (scanners, etc) results. (OK with developed PoC)
* Any asset whose source code does not exist in this repository (including, but not limited
to, any and all web properties not explicitly listed on this page)
* Programs in the Solana Program Library, such as SPL Token. Please refer to the
[SPL security policy](https://github.com/solana-labs/solana-program-library/security/policy).

### Eligibility:
* Submissions _MUST_ include an exploit proof-of-concept to be considered eligible
* The participant submitting the bug report shall follow the process outlined within this document
* Valid exploits can be eligible even if they are not successfully executed on a public cluster
* Multiple submissions for the same class of exploit are still eligible for compensation, though may be compensated at a lower rate, however these will be assessed on a case-by-case basis
* Participants must complete KYC and sign the participation agreement here when the registrations are open https://solana.foundation/kyc. Security exploits will still be assessed and open for submission at all times. This needs only be done prior to distribution of tokens.

### Duplicate Reports
Compensation for duplicative reports will be split among reporters with first to report taking priority using the following equation
```
R: total reports
ri: report priority
bi: bounty share

bi = 2 ^ (R - ri) / ((2^R) - 1)
```
#### Bounty Split Examples
| total reports | priority | share  |   | total reports | priority | share  |   | total reports | priority | share  |
| ------------- | -------- | -----: | - | ------------- | -------- | -----: | - | ------------- | -------- | -----: |
| 1             | 1        | 100%   |   | 2             | 1        | 66.67% |   | 5             | 1        | 51.61% |
|               |          |        |   | 2             | 2        | 33.33% |   | 5             | 2        | 25.81% |
| 4             | 1        | 53.33% |   |               |          |        |   | 5             | 3        | 12.90% |
| 4             | 2        | 26.67% |   | 3             | 1        | 57.14% |   | 5             | 4        |  6.45% |
| 4             | 3        | 13.33% |   | 3             | 2        | 28.57% |   | 5             | 5        |  3.23% |
| 4             | 4        |  6.67% |   | 3             | 3        | 14.29% |   |               |          |        |

### Payment of Bug Bounties:
* Bounties are currently awarded on a rolling/weekly basis and paid out within 30 days upon receipt of an invoice.
* Bug bounties that are paid out in SOL are paid to stake accounts with a lockup expiring 12 months from the date of delivery of SOL.
* **Note: payment notices need to be sent to ap@solana.org within 90 days of receiving payment advice instructions.** Failure to do so may result in forfeiture of the bug bounty reward.
