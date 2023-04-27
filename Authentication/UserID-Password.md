# User ID and Password Authentication

This checklist is designed to ensure the security of user authentication. It includes a series of steps and best practices for protecting user IDs and passwords and preventing unauthorized access to user accounts.

## 🔨 User Registration

The following two checklists should be considered for the identifiers that can be used as a User ID.

**Username**

| #️⃣  | ✅Items                                                                                                                                                             | ⚠️Severity |       🗡️Attacks        |  🔗Sources  |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :--------------------: | :---------: |
|  1  | Verify: Usernames are case insensitive </br> Reason: Prevent confusion between 'smith' and 'Smith'                                                                  |    Low     |    `Impersonation`     | [ACS](#ACS) |
|  2  | Verify: Usernames are unique </br> Reason: Prevent a username to be used for multiple accounts                                                                      |    High    |    `Impersonation`     | [ACS](#ACS) |
|  3  | Verify: Usernames must be at least 6 characters long </br> Reason: Protection against guessing attacks                                                              |    High    |     `Bruteforcing`     | [ACS](#ACS) |
|  4  | Verify: Usernames are not the same as some system-reserved names such as root, admin, administrator, etc. </br> Reason: Prevent user from receiving high privileges |    High    | `Privilege Escalation` | [ACS](#ACS) |
|  5  | Verify: Disallow common and easily guessable usernames such as test, user, admin, etc. </br> Reason: Make it harder for an attacker to predict someone's username   |    Low     |     `Bruteforcing`     |     ⛔      |

**Email**

| #️⃣  | ✅Items                                                                                                                                                                                                                                       | ⚠️Severity |    🗡️Attacks    |   🔗Sources   |
| :-: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-------------: | :-----------: |
|  1  | Verify: Emails are no longer than 254 characters in length </br> Reason: Protection against denial of service                                                                                                                                 |    Low     |      `DoS`      | [IVCS](#IVCS) |
|  2  | Verify: Email receives a PIN or a URL token for verification. The PIN and URL token Checklists under [Forgot Credentials](#forgot-credentials) must be used for this </br> Reason: Verify that a person has access to the email they provided |    High    | `Impersonation` | [IVCS](#IVCS) |
|  3  | Verify: Emails are unique </br> Reason: Prevent an email to be used for multiple account                                                                                                                                                      |    High    | `Impersonation` | [IVCS](#IVCS) |

**Password**

| #️⃣  | ✅Items                                                                                                                                                                                                                 | ⚠️Severity |    🗡️Attacks    |                      🔗Sources                      |
| :-: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-------------: | :-------------------------------------------------: |
|  1  | Verify: A password is at least 8 characters in length </br> Reason: Protect against guessing since shorter passwords can be guessed                                                                                     |    High    | `Bruteforcing`  |       [ACS](#ACS), [NISP800-63B](#SP800-63B)        |
|  2  | Verify: A password's maximum length is at least 64 characters </br>Reason: Protect against password length DoS attacks                                                                                                  |    Low     |      `DoS`      | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  3  | Verify: All ASCII characters, Unicode, and white spaces are considered valid input </br> Reason: Allow users to create a complex password which will make it hard to guess                                              |   Medium   | `Bruteforcing`  |               [SP800-63B](#SP800-63B)               |
|  4  | Verify: Password contains characters from the following categories: Upper and lower case alphabets, numbers, special characters and unicodes </br> Reason: Increases passwords entropy which makes it harder to predict |    High    | `Bruteforcing`  |                    [MS365](#MS)                     |
|  5  | Verify: Common or previously breached passwords are blocked </br>Reason: Protect against password guessing                                                                                                              |   Medium   | `Bruteforcing`  | [ACS](#ACS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  6  | Verify: The user is not asked to set password hints</br> Reason: Reveals information about the password, which makes it easier to guess                                                                                 |    High    | `Bruteforcing`  |       [ASVS](#ASVS), [SP800-63B](#SP800-63B)        |
|  7  | Verify: The user is notified of an account creation via email </br> Reason: The user is aware of the use of their email on an external website                                                                          |   Medium   | `Impersonation` |       [ASVS](#ASVS), [SP800-63B](#SP800-63B)        |

---

## 📦 Credential Storage

| #️⃣  | ✅Items                                                                                                                                                                                              | ⚠️Severity |          🗡️Attacks           |                       🔗Sources                       |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :--------------------------: | :---------------------------------------------------: |
|  1  | Verify: Passwords are hashed before storing in the database </br> Reason: In case of a password leak, the hashed passwords won't allow access to an account                                          |    High    | `Injection`, `Impersonation` | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  2  | Verify: User IDs are stored securely in the database by either hashing or encrypting them </br> Reason: In case of a data breach, user IDs are unreadable                                            |    Low     |           `Theft`            |                          ⛔                           |
|  3  | Verify: Only approved encrypting and hashing algorithms are used </br> Reason: Unapproved hashing algorithms are insecure since they can be bypassed and clear text values can be extracted          |    High    |        `Bruteforcing`        | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  4  | Verify: Salt is used before hashing passwords </br> Reason: Makes passwords even more complex by adding additional characters to it. Also helps make same passwords used by multiple users different |    High    |        `Bruteforcing`        | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  5  | Verify: Salt is at least 32 bits in size </br> Reason: Makes it challenging to be guessed                                                                                                            |    High    |        `Bruteforcing`        | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  6  | Verify: Salt is unique for each password </br> Reason: When two users choose the same password, their hash won't be the same as each password is appended to a unique salt                           |    High    |        `Bruteforcing`        | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  7  | Verify: Salt is generated by using secure random algorithms </br> Reason: Makes it hard to predict the value of the hash                                                                             |    High    |        `Bruteforcing`        | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  8  | Verify: Peppering can be used in addition to salting </br> Reason: Adds additional security to the passwords. Preferred for sensitive accounts                                                       |    Low     |        `Bruteforcing`        |                    [OPSCS](#PSCS)                     |
|  9  | Verify: If peppering is used, it is stored in a password vault </br> Reason: More secure than storing in the database                                                                                |    High    |        `Bruteforcing`        |                    [OPSCS](#PSCS)                     |
| 10  | Verify: Pepper rotation policy is in place </br> Reason: In case of a leak, rotation policy will invalidate the older pepper                                                                         |    High    |   `Bruteforcing`, `Theft`    |                    [OPSCS](#PSCS)                     |
| 11  | Verify: Pepper is produced by using secure random algorithms </br> Reason: Makes it challenging to guess the value                                                                                   |    High    |        `Bruteforcing`        |                    [OPSCS](#PSCS)                     |

---

## 🚦 User Verification

| #️⃣  | ✅Items                                                                                                                                                                                                                                                          |  ⚠️Severity   |       🗡️Attacks        |              🔗Sources               |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------: | :--------------------: | :----------------------------------: |
|  1  | Verify: If account lockout is in place for the provided user ID, authentication process should not even start </br> Reason: Response time delays during authentication can reveal if an account exists in the database or not. This is also a waste of resources |    Medium     |     `Bruteforcing`     |                  ⛔                  |
|  2  | Verify: An account is locked after a certain number of failed attempts </br> Reason: Rate limiting mechanism to prevent guessing                                                                                                                                 |     High      |     `Bruteforcing`     |      [ACS](#ACS), [ASVS](#ASVS)      |
|  3  | Verify: Account lockout is not for a fixed time rather, it should increase exponentially with each failed login attempt </br> Reason: Rate limiting mechanism that makes it challenging for guessing attacks to occur                                            |    Medium     |     `Bruteforcing`     | [ACS](#ACS), [SP800-63B](#SP800-63B) |
|  4  | Verify: The user is notified via email when an account lockout takes place </br> Reason: The user must be aware if someone tried to guess their account so they can change their password                                                                        |     High      |     `Bruteforcing`     |                  ⛔                  |
|  5  | Verify: Error responses for failed login attempts are generic such as: <em>user ID or password is incorrect</em> </br> Reason: Too specific error messages can reveal information about the user's account                                                       |    Medium     |     `Bruteforcing`     |             [ACS](#ACS)              |
|  6  | Verify: HTTP status codes during authentication are generic </br> Reason: Too specific error messages can reveal information about the user's account                                                                                                            | Informational |     `Bruteforcing`     |             [ACS](#ACS)              |
|  7  | Verify: Response time for user ID and password checks during authentication should be the same </br> Reason: The difference in response time can indicate if credentials was found in the database or not                                                        |    Medium     |     `Bruteforcing`     |             [ACS](#ACS)              |
|  8  | Verify: All authentication cookies must follow implementation guidelines in [Session Management](../Session.md) </br> Reason: Implement authentication cookies securely                                                                                          |     High      | `Eavesdropping`, `XSS` | [ACS](#ACS), [SP800-63B](#SP800-63B) |
| 19  | Verify: The user is sent an email notification if login occurs from a different device, IP, or geo-location </br> Reason: In case someone else logged into the user's account without their consent                                                              |      Low      |    `Impersonation`     |             [ACS](#ACS)              |

---

## 🔃 Credential Reset

| #️⃣  | ✅Items                                                                                                                                                                                                                                | ⚠️Severity |    🗡️Attacks    |              🔗Sources               |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-------------: | :----------------------------------: |
|  1  | Verify: The user is required to reauthenticate before a password or user ID reset </br> Reason: Ensures that the actual user is making a change, not someone else                                                                      |    High    | `Impersonation` | [ACS](#ACS), [SP800-63B](#SP800-63B) |
|  2  | Verify: The user is required to type the new password twice </br> Reason: Helps prevent typos                                                                                                                                          |    Low     |       ⛔        |       [SP800-63B](#SP800-63B)        |
|  3  | Verify: Reuse of old passwords is not allowed </br> Reason: Users are likely to use the same password across many websites, which can be a risk if one of those websites is compromised                                                |    Low     | `Bruteforcing`  |                  ⛔                  |
|  4  | Verify: When a new credential is set, it must follow [Registration](#user-registration) and [Credential Storage](#📦credential-storage) guidelines for secure handling and storage</br> Reason: Ensure that new credentials are secure |    High    | `Impersonation` |                  ⛔                  |
|  5  | Verify: Email notification is sent to this user when a credential change is successful </br> Reason: Incase the user did not authorize a password change, they should know someone else did                                            |   Medium   | `Impersonation` | [ACS](#ACS), [SP800-63B](#SP800-63B) |

---

## 🤔 Forgot Credentials

When a user chooses forgot credentials, their identity can be verified through multiple ways:

-   Generate a PIN that can be sent to the user with the provided email. This PIN needs to be confirmed before a password reset is allowed
-   Create a token and pass it into the query string, create a limited session around that unique URL, and send it to the user's email
-   Recovery/Backup codes can also be used to give access when the user forgets their password

</br>

The following items must be considered for using PINS, URL tokens or Backup Codes.

**PIN**

| #️⃣  | ✅Items                                                                                                                                                                                                                                           | ⚠️Severity |           🗡️Attacks            |   🔗Sources   |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------------: | :-----------: |
|  1  | Verify: The PIN must be 6 to 12 digits long </br> Reason: Increase complexity which helps against guessing                                                                                                                                        |    High    |         `Bruteforcing`         | [FPCS](#FPCS) |
|  2  | Verify: The PIN is unique and is generated using secure random algorithms </br> Reason: Provides additional protection against guessing since a truly random value is hard to predict                                                             |    High    |         `Bruteforcing`         | [FPCS](#FPCS) |
|  3  | Verify: The PIN is sent to either email or phone number that the user provided </br> Reason: The possession of the PIN verifies their identity                                                                                                    |    High    |        `Impersonation`         | [FPCS](#FPCS) |
|  4  | Verify: A limited time session is permitted for the PIN until it expires </br> Reason: In case the PIN leaks through an email/phone compromise, it is no longer active after a few minutes                                                        |    High    |    `Impersonation`, `Theft`    | [FPCS](#FPCS) |
|  5  | Verify: Use [Credential Storage](#credential-storage) policies for hashing the PIN when it's being stored </br> Reason: Helps against database compromise or PIN leakage                                                                          |    High    |            `Theft`             | [FPCS](#FPCS) |
|  6  | Verify: A generic message is shown if the email provided exists or not such as: "A PIN will be sent to the provided email if it exists in the database" </br> Reason: Too specific error messages can reveal information about the user's account |   Medium   |         `Bruteforcing`         | [FPCS](#FPCS) |
|  7  | Verify: The PIN is checked for validity before the user can set the set a new password </br> Reason: The likelihood of a logic error is high when PIN validity check and password reset happen together                                           |    Low     | `Logic Error`, `Impersonation` | [FPCS](#FPCS) |
|  8  | Verify: The PIN in invalidated once it has been used </br> Reason: Prevent the reuse of the PIN in case an attacker gets a hold of it                                                                                                             |    High    |    `Impersonation`, `Theft`    | [FPCS](#FPCS) |

**URL Token**

| #️⃣  | ✅Items                                                                                                                                                                                   | ⚠️Severity |        🗡️Attacks         |   🔗Sources   |
| :-: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :-----------: |
|  1  | Verify: The token is generated using secure random algorithms </br> Reason: Protection against guessing since a random value is hard to predict                                           |    High    |      `Bruteforcing`      | [FPCS](#FPCS) |
|  2  | Verify: Use [Credential Storage](#credential-storage) checklist for hashing the token for secure storage </br> Reason: Helps against database compromise or token leakage                 |    High    |         `Theft`          | [FPCS](#FPCS) |
|  3  | Verify: URL is hard-coded rather than relying on the host header </br> Reason: Protection against host header injection                                                                   |   Medium   |          `HHi`           | [FPCS](#FPCS) |
|  4  | Verify: The reset password page uses the Referrer Policy tag with the `noreferrer` value </br> Reason: Prevention against referrer leakage                                                |   Medium   |    `Referrer Leakage`    | [FPCS](#FPCS) |
|  5  | Verify: A limited session is allowed for the URL token before it expires </br> Reason: In case the token leaks through an email/phone compromise, is no longer active after a few minutes |    High    | `Impersonation`, `Theft` | [FPCS](#FPCS) |
|  6  | Verify: The token is checked for validity before the user can set the set a new password </br> Reason: Ensures that the request is coming from the intended user                          |    High    |     `Impersonation`      | [FPCS](#FPCS) |
|  7  | Verify: The token is invalidated once it has been used </br> Reason: Prevent the reuse of the token                                                                                       |    High    | `Impersonation`, `Theft` | [FPCS](#FPCS) |

**Additional Authenticator Factor**

Recovery/Backup code security checklist can be viewed [here](./MFA/Authenticator-Types.md#lookup-secrets)

⚠️ Once the user has been confirmed, then [Credential Reset](#credential-reset) checklist must be used

---

## 📋 Authentication Policies

| #️⃣  | ✅Items                                                                                                                                                                                                                        | ⚠️Severity |        🗡️Attacks         |                       🔗Sources                       |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------: | :----------------------: | :---------------------------------------------------: |
|  1  | Verify: All authentication-related events must be logged, such as account lockout, account creation, account login, etc. </br> Reason: Helps in detecting and investigating security incidences                                |    High    |  `Insufficient Logging`  |                      [ACS](#ACS)                      |
|  2  | Verify: Passwords and private user IDs aren't logged </br> Reason: Sensitive user data exists in plaintext                                                                                                                     |    High    |  `Information Leakage`   |                      [LCS](#LCS)                      |
|  3  | Verify: All user-supplied input i.e. passwords, user IDs, PINs etc., should never be trusted and must be validated </br> Reason: Protect against injection or denial of service attacks                                        |    High    |       `Injection`        |                      [ACS](#ACS)                      |
|  4  | Verify: TLS (HTTPS) and `Strict-Transport-Security` header is enable for every authentication process </br> Reason: Network traffic is encrypted which helps prevent eavesdropping                                             |    High    |     `Eavesdropping`      |         [ACS](#ACS), [SP800-63B](#SP800-63B)          |
|  5  | Verify: Rate limiting mechanisms exist </br> Reason: Prevention against guessing and denial of service                                                                                                                         |    High    |  `Bruteforcing`, `DoS`   |                [SP800-63B](#SP800-63B)                |
|  6  | Verify: Password expiration is in place </br> Reason: Incase password leaks it is not active forever                                                                                                                           |   Medium   | `Impersonation`, `Theft` |         [ACS](#ACS), [SP800-63B](#SP800-63B)          |
|  7  | Verify: The application requires the user to reauthenticate for sensitive features such as payment, updating password or user ID etc.</br> Reason: Ensures that request is coming from the intended user                       |    High    |     `Impersonation`      |         [ACS](#ACS), [SP800-63B](#SP800-63B)          |
|  8  | Verify: User has the option to set a second or multi-factor authentication </br> Reason: Password leak won't have any impact because the second factor is still not compromised                                                |    High    | `Impersonation`, `Theft` | [PSCS](#PSCS), [ASVS](#ASVS), [SP800-63B](#SP800-63B) |
|  9  | Verify: Re-authentication takes place after a period of inactivity </br> Reason: This helps to prevent unauthorized access to user accounts and sensitive information, even if a user's device or session has been compromised |    High    |     `Impersonation`      |         [ACS](#ACS), [SP800-63B](#SP800-63B)          |

---

## 🔴 Authentication in Production

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                      | ⚠️Severity |        🗡️Attacks        | 🔗Sources |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------: | :-------: |
|  1  | Verify: Regularly monitor log activity </br> Reason: To detect any suspicious activity such as multiple failed login attempts                                                                                                                                                |    High    |     `Bruteforcing`      |    ⛔     |
|  2  | Verify: Periodically review registered user IDs for suspicious entries </br> Reason: Ensure that registered usernames are not impersonating someone else, using profanity, or containing malicious characters                                                                |   Medium   |  `Website Defacement`   |    ⛔     |
|  3  | Verify: Third party software or libraries used for password authentication are updated to the most recent version and are regularly patched </br> Reason: Vulnerability in a third party resource can grant an attacker unauthorized access                                  |    High    | `Vulnerable Dependency` |    ⛔     |
|  4  | Verify: Conduct regular security assessments, vulnerability scans, and penetration testing to identify vulnerabilities in custom and third-party code </br> Reason: Identify any security vulnerabilities that might have appeared in password authentication implementation |    High    |  `Unauthorized Access`  |    ⛔     |

---

**🔗 Sources:**

Microsoft (MS):

-   <a href="https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations?view=o365-worldwide#requiring-the-use-of-multiple-character-sets" target="_blank" id="MS">[MS365] Microsoft 365 Password Recommendations </a>

Open Web Application Security Project (OWASP):

-   <a href="https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v2-authentication" target="_blank" id="ASVS">[ASVS] Application Security Verification Standard - Authentication</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" target="_blank" id="ACS">[ACS] Authentication Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" target="_blank" id="PSCS">[PSCS] Password Storage Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html" target="_blank" id="FPCS">[FPCS] Forgot Password Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#email-address-validation" target="_blank" id="IVCS">[IVCS] Input Validation Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" target="_blank" id="LCS">[LCS] Logging Cheat Sheet</a>

National Institute of Standards and Technology (NIST):

-   <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#-5112-memorized-secret-verifiers" target="_blank" id="SP800-63B">[SP800-63B] 5.1.1.2 Memorized Secret Verifiers</a>
