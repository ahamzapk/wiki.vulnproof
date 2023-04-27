# Authenticator Management

Several events can occur over the lifecycle of a user’s authenticator that affects that authenticator’s use. These events include authenticator registration, verification, reset, and loss. This section describes the actions to be taken in response to those events.

## 🔨 Authenticator Registration

| #️⃣  | ✅Items                                                                                                                                                                                                          | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: The website supports at least two factors </br> Reason: Two or more factors are more secure than only one factor                                                                                         |    High    | `Bruteforcing`, `Theft`  | [SP800-63B](#SP800-63B) |
|  3  | Verify: If a user tries to register an authenticator, they should be re-authenticated by using the existing factor </br> Reason: Confirms that the actual user is registering an authenticator, not someone else |    High    |     `Impersonation`      | [SP800-63B](#SP800-63B) |
|  4  | Verify: Guidelines for the [Type](./Authenticator-Types.md) of authenticator being registered are considered </br> Reason: Ensure that unique security policies for each authenticator are considered            |    High    |            ⛔            | [SP800-63B](#SP800-63B) |
|  5  | Verify: Authenticator expiration should be in place </br> Reason: Prevent an attacker from having access forever                                                                                                 |    Low     | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |

---

## 🚦 Authenticator Verification

| #️⃣  | ✅Items                                                                                                                                                                                                               | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: Stop the execution and return an expired message if the authenticator is expired </br> Reason: Limit the use of resources                                                                                     |   Medium   |         `Theft`          | [SP800-63B](#SP800-63B) |
|  2  | Verify: Authenticator verification should happen after [Memorized Secret](./Authenticator-Types.md#something-you-know) </br> Reason: Revealing information to an attacker about which the second factor is being used |    Low     |  `Information Leakage`   | [SP800-63B](#SP800-63B) |
|  3  | Verify: Authenticator verification should take place in a limited time </br> Reason: Less time an attacker has to respond                                                                                             |    High    | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |
|  4  | Verify: An account is locked after a certain number of failed verification attempts </br> Reason: Prevents an attacker from guessing the verification token/secret                                                    |    High    |      `Bruteforcing`      | [SP800-63B](#SP800-63B) |

---

## 🔃 Authenticator Reset

| #️⃣  | ✅Items                                                                                                                                                                                        | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: The user should be reauthenticated before an authenticator reset takes place </br> Reason: Ensures that the actual user is making a change, not someone else                           |    High    |     `Impersonation`      | [SP800-63B](#SP800-63B) |
|  2  | Verify: The user is required to verify the authenticator's output before it is accepted </br> Reason: Confirms the possession of the authenticator                                             |    High    | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |
|  3  | Verify: Guidelines for the [Type](./Authenticator-Types.md) of authenticator being registered must be considered </br> Reason: A new authenticator is installed securely                       |    High    |            ⛔            | [SP800-63B](#SP800-63B) |
|  4  | Verify: Once a new authenticator is established, the website should revoke the previous authenticator </br> Reason: In case an attacker gets a hold of the old authenticator, it wouldn't work |    High    | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |

---

## 😕 Authenticator Lost

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                            | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: When a user reports an authenticator lost, they should be reauthenticated </br> Reason: Confirms that the actual user is making the lost claim not someone else                                                                                                            |    High    |     `Impersonation`      | [SP800-63B](#SP800-63B) |
|  2  | Verify: If a user reports a lost authenticator during the verification stage at login, a PIN or token URL strategy from [Credential Reset](../UserID-Password.md#credential-reset) must be followed</br> Reason: Establishes a secure way for a user to change their authenticator |    High    | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |
|  3  | Verify: The lost authenticator no longer works with the user's account </br> Reason: Incase an attacker gets a hold of the authenticator, it shouldn't work                                                                                                                        |    High    | `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |

---

## 📋 Authenticator Policies

| #️⃣  | ✅Items                                                                                                                                                                                                                                         | ⚠️Severity |       🗡️Attacks        |                      🔗Sources                      |
| :-: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :--------------------: | :-------------------------------------------------: |
|  1  | Verify: All authenticator-related events are logged. Such as registering a new authenticator, lost authenticator, incorrect authenticator value, etc. </br> Reason: Helps in detecting and investigating security incidences                    |    High    | `Insufficient Logging` | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  2  | Verify: All user-supplied input i.e., PINs, secrets, code, etc., should never be trusted and must be validated </br> Reason: Prevents injection or denial of service attacks                                                                    |    High    |   `Injection`, `DoS`   |                     [ACS](#ACS)                     |
|  3  | Verify: TLS (HTTPS) and `Strict-Transport-Security` header are enabled for every authentication process </br> Reason: Network traffic is encrypted which prevents eavesdropping                                                                 |    High    |    `Eavesdropping`     |             [ACS](#ACS), [ASVS](#ASVS)              |
|  4  | Verify: Rate-limiting mechanisms exist </br> Reason: Prevents guessing and denial of service                                                                                                                                                    |    High    | `Bruteforcing`, `DoS`  | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  5  | Verify: At least two factors can be used. "something you know" must be following by either a "something you have" or "something you are" </br> Reason: Decreases the likelihood of account compromise since possession of two factors is needed |    High    |        `Theft`         | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  6  | Verify: The website should maintain a record of all authenticators that are associated with an account </br> Reason: Revocation and deletion of authenticators are possible in case of compromise                                               |    High    |        `Theft`         |               [SP800-63B](#SP800-63B)               |
|  7  | Verify: Email notifications must be sent for sensitive operations such as authenticator registration, reset, lost, and account lockout </br> Reason: In case the user didn't authorize these operations, the notification will alert them       |    High    |    `Impersonation`     | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |

---

## 🔴 Authenticator in Production

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                          | ⚠️Severity |        🗡️Attacks        | 🔗Sources |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------: | :-------: |
|  1  | Verify: Regularly monitor log activity </br> Reason: To detect any suspicious activity such as multiple failed authenticator attempts                                                                                                                                            |    High    |     `Impersonation`     |    ⛔     |
|  2  | Verify: Periodically review registered authenticators for suspicious entries </br> Reason: Ensure that unauthorized authenticators aren't associate with an account                                                                                                              |    High    |  `Unauthorized Access`  |    ⛔     |
|  3  | Verify: Third party software or libraries used by multi-factor authentication are updated to the most recent version and are regularly patched </br> Reason: Vulnerability in a third party resource can grant an attacker unauthorized access                                   |    High    | `Vulnerable Dependency` |    ⛔     |
|  4  | Verify: Conduct regular security assessments, vulnerability scans, and penetration testing to identify vulnerabilities in custom and third-party code </br> Reason: Identify any security vulnerabilities that might have appeared in multi-factor authentication implementation |    High    |  `Unauthorized Access`  |    ⛔     |

**🔗 Sources:**

Open Web Application Security Project (OWASP):

-   <a href="https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v2-authentication" target="_blank" id="ASVS">[ASVS] Application Security Verification Standard - Authentication</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" target="_blank" id="ACS">[ACS] Authentication Cheat Sheet</a>

National Institute of Standards and Technology (NIST):

-   <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#5-authenticator-and-verifier-requirements" target="_blank" id="SP800-63B">[SP800-63B] 5 Authenticator and Verifier Requirements</a>
