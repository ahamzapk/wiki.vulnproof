This checklist is a guide for securing authorization on a website. It outlines a series of steps and best practices that should be taken to ensure that only authorized users can access sensitive information and perform certain actions on a website.

## 🪪 Authorization ID

| #️⃣  | ✅Items                                                                                                                                                                                  | ⚠️Severity |       🗡️Attacks       |         🔗Sources          |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-------------------: | :------------------------: |
|  1  | Verify: Ensure role ID is not revealed in URL, cookies, session, local storage, and response header </br> Reason: An attacker can steal the ID and gain unauthorized access              |    High    |        `Theft`        | [ACS](#ACS), [ASVS](#ASVS) |
|  2  | Verify: If role ID is accessible to the user, ensure that it is validated before it is processed </br> Reason: Prevents malicious input by an attacker                                   |    High    |      `Injection`      | [ACS](#ACS), [ASVS](#ASVS) |
|  3  | Verify: Rate limiting mechanisms exist on the role ID</br> Reason: Protection against guessing and Denial of Service (DoS) attacks                                                       |   Medium   | `Bruteforcing`, `DoS` |             ⛔             |
|  4  | Verify: If role ID is accessible to the user, it is created using secure random function </br> Reason: The role ID is not guessable                                                      |   Medium   |    `Bruteforcing`     | [ACS](#ACS), [ASVS](#ASVS) |
|  3  | Verify: Authorization ID exchange takes place over TLS (HTTPS) </br> Reason: Encrypted channel that prevent eavesdropping                                                                |    High    |    `Eavesdropping`    |             ⛔             |
| 10  | Verify: Data related to Authorization is stored server side by using secure encryption and hashing algorithms </br> Reason: Provides additional security incase of a database compromise |    High    |        `Theft`        |             ⛔             |

---

## 📋 Authorization Policies

| #️⃣  | ✅Items                                                                                                                                                                               | ⚠️Severity |         🗡️Attacks         |         🔗Sources          |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-----------------------: | :------------------------: |
|  1  | Verify: If a library is used for authorization, ensure it is not misconfigured </br> Reason: Default configurations or misconfigurations can grant unauthorized access to an attacker |    High    |    `Misconfiguration`     |        [ACS](#ACS)         |
|  2  | Verify: Libraries used for authorization are not vulnerable </br> Reason: An attacker can use the vulnerable library to escalate their privileges                                     |    High    | `Vulnerable Dependencies` |        [ACS](#ACS)         |
|  3  | Verify: Sensitive routes cannot be accessed without proper authorization </br> Reason: Prevent directory traversal                                                                    |    High    |   `Directory Traversal`   | [ACS](#ACS), [ASVS](#ASVS) |
|  4  | Verify: If location-based authorization is enabled, ensure that VPN, proxy, or changing browser geolocation cannot circumvent it </br> Reason: Prevent location spoofing              |   Medium   |    `Location Spoofing`    |        [ACS](#ACS)         |
|  5  | Verify: Unauthorized access isn't granted through Insecure Direct Object Reference (IDOR)</br> Reason: Prevent unauthorized access by IDOR                                            |   Medium   |          `IDOR`           | [ACS](#ACS), [ASVS](#ASVS) |
|  6  | Verify: Authorization checks are enforced for each page on the frontend </br> Reason: Cannot steal statically typed information of frontend pages                                     |    Low     |   `Directory Traversal`   |        [ACS](#ACS)         |
|  7  | Verify: Ensure that authorization is validated on client and server side </br> Reason: Prevent injection and Man-in-The-Middle (MiTM) attacks                                         |   Medium   |    `Injection`, `MiTM`    |        [ACS](#ACS)         |
|  8  | Verify: Least privilege is enforced </br> Reason: Minimize attack surface incase someone has unauthorized access to someone's account                                                 |    High    |  `Privilege Escalation`   | [ACS](#ACS), [ASVS](#ASVS) |
|  9  | Verify: Deny by default when no authorization roles match </br> Reason: Attempts by unauthorized users to gain access are assumed to be harmful and are denied access                 |    High    |  `Privilege Escalation`   |        [ACS](#ACS)         |
| 10  | Verify: Validate permissions on each request </br> Reason: Ensure all requests are coming from the right authority                                                                    |   Medium   |      `Impersonation`      |        [ACS](#ACS)         |
| 11  | Verify: Ensure appropriate logging for failed authorization attempts </br> Reason: Used for investigation in case of a breach or an attempt of a breach                               |    High    |  `Insufficient Logging`   |        [ACS](#ACS)         |
| 12  | Verify: Proper error handling of insufficient privileges takes place </br> Reason: Terminate the request for unauthorized paths                                                       |    High    |  `Privilege Escalation`   |        [ACS](#ACS)         |

---

## 🔴 Authorization in Production

| #️⃣  | ✅Items                                                                                                                                                                                                                                                            | ⚠️Severity |                              🗡️Attacks                               | 🔗Sources |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------: | :------------------------------------------------------------------: | :-------: |
|  1  | Verify: Authorization roles are regularly reviewed and updated </br> Reason: Ensure each person only has the access they need                                                                                                                                      |    High    |            `Unauthorized Access`, `Privilege Escalation`             |    ⛔     |
|  2  | Verify: Audit logs are monitored regularly for anomalies </br> Reason: Identify attacks that someone tried on a user                                                                                                                                               |    High    |             `Directory Traversal`, `Unauthorized Access`             |    ⛔     |
|  3  | Verify: Third party software or libraries used for authorization are updated to the most recent version and are regularly patched </br> Reason: Vulnerability in a third party resource can grant an attacker unauthorized access                                  |    High    | `Unauthorized Access`, `Privilege Escalation`, `Directory Traversal` |    ⛔     |
|  4  | Verify: Conduct regular security assessments, vulnerability scans, and penetration testing to identify vulnerabilities in custom and third-party code </br> Reason: Identify any security vulnerabilities that might have appeared in authorization implementation |    High    |                        `Unauthorized Access`                         |    ⛔     |

---

**🔗 Sources:**

Open Web Application Security Project (OWASP):

-   <a href="https://github.com/OWASP/ASVS/blob/master/4.0/en/0x12-V4-Access-Control.md" target="_blank" id="ASVS">(ASVS) Application Security Verification Standard - Access Control</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html#enforce-authorization-checks-on-static-resources" target="_blank" id="ACS">(ACS) Authorization Cheat Sheet</a>
