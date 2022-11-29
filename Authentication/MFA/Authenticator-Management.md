A number of events can occur over the lifecycle of a subscriber’s authenticator that affect that authenticator’s use. These events include authenticator registration, verification, reset, and loss. This section describes the actions to be taken in response to those events.

## 🍎 General Policies

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                                                            | ⚠️Severity |         🗡️Attacks          |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------: | :------------------------: |
|  1  | <em>Verify:</em> All authenticator related events are logged. Such as registering new authenticator, authenticator lost, incorrect authenticator value etc. </br> <em>Reason:</em> Trigger alerts when abnormal events occur. Also, helps with investigations      |    High    |   `Insufficient Logging`   |
|  2  | <em>Verify:</em> All user supplied input i.e. PINs, secrets, code etc., should never be trusted and must be validated </br> <em>Reason:</em> Prevention against injection or Denial of Service (DOS) attacks                                                       |    High    | `SQLi` `LDAPi` `XSS` `DoS` |
|  3  | <em>Verify:</em> TLS (HTTPS) and `Strict-Transport-Security` header are enable for every authentication process </br> <em>Reason:</em> Network traffic is encrypted which helps prevents eavesdropping                                                             |    High    |      `Eavesdropping`       |
|  4  | <em>Verify:</em> Rate limiting mechanisms exist </br> <em>Reason:</em> Prevention against guessing and DoS                                                                                                                                                         |    High    |    `Bruteforing` `DoS`     |
|  5  | <em>Verify:</em> At least two factors can be used. "something you know" must be following by either a "something you have" or "something you are" </br> <em>Reason:</em> Decreases the likelihood of account compromise since possession of two factor is needed   |    High    |          `Theft`           |
|  6  | <em>Verify:</em> The website should maintain a record of all authenticators that are associated with an account </br> <em>Reason:</em> Helps with revocation and deletion of authenticators                                                                        |    High    |          `Theft`           |
|  7  | <em>Verify:</em> Email notifications must be sent for sensitive operations such as authenticator registration, reset, lost and account lockout </br> <em>Reason:</em> Incase the user didn't authorize these operations, the notification will alert them about it |    High    |      `Impersonation`       |

## 🔨 Authenticator Registration

Following items must be considered for authenticator registration process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                         |  ⚠️Severity   |        🗡️Attacks        |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------: | :---------------------: |
|  1  | <em>Verify:</em> Website supports at least two factors</br> <em>Reason:</em> Two or more factors are more secure than only one factor                                                                                           |     High      | `Bruteforcing` `Theft`  |
|  2  | <em>Verify:</em> Authenticator registration should take place during user registration or when the user chooses </br> <em>Reason:</em> Decision up to the website owner to make                                                 | Informational |           ⛔            |
|  3  | <em>Verify:</em> If a user tries to register an authenticator, they should be reauthenticated by using the existing factor </br> <em>Reason:</em> Confirm that the actual user is registering an authenticator not someone else |     High      |     `Impersonation`     |
|  4  | <em>Verify:</em> Guidelines for the [Type](./Types.md) of authenticator being registered are considered </br> <em>Reason:</em> Ensure that unique security policies for each authenticator are considered                       |     High      |           ⛔            |
|  5  | <em>Verify:</em> Authenticator expiration should be set </br> <em>Reason:</em> Prevent an attacker to have access forever                                                                                                       |    Medium     | `Impersonation` `Theft` |

## 🚦 Authenticator Verification

Following items that be considered for authenticator verification process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                              | ⚠️Severity |        🗡️Attacks        |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------: |
|  1  | <em>Verify:</em> If authenticator expiration policy exists, stop the execution and return an expired message if the authenticator is expired </br> <em>Reason:</em> Limit the use of resources                       |   Medium   |         `Theft`         |
|  2  | <em>Verify:</em> Authenticator verification should happens after [Memorized Secret](Types.md#something-you-know) </br> <em>Reason:</em> Revealing information to an attacker about which second factor is being used |    Low     |  `Information Leakage`  |
|  3  | <em>Verify:</em> Authenticator verification should take place in a limited time</br> <em>Reason:</em> Less time an attacker has to respond                                                                           |    High    | `Impersonation` `Theft` |
|  4  | <em>Verify:</em> An account is locked after a certain number of failed attempts</br> <em>Reason:</em> Limit the use of guessing                                                                                      |    High    |      `Bruteforing`      |

## 🔃 Authenticator Reset

Following items must be considered for authenticator reset process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                          | ⚠️Severity |        🗡️Attacks        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------: |
|  1  | <em>Verify:</em> User should be reauthenticated before an authenticator reset takes place </br> <em>Reason:</em> Ensure that the actual user is making a change not someone else                                 |    High    |     `Impersonation`     |
|  3  | <em>Verify:</em> Guidelines for the [Type](./Types.md) of authenticator being registered must be considered </br> <em>Reason:</em> Ensure that unique security policies for each authenticator are considered    |    High    |           ⛔            |
|  4  | <em>Verify:</em> Once a new authenticator is established, the website should revoke the previous authenticator </br> <em>Reason:</em> Incase an attacker gets a hold of the old authenticator, it shouldn't work |    High    | `Impersonation` `Theft` |

## 😕 Authenticator Lost

Following items must be considered for authenticator lost process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                                         | ⚠️Severity |        🗡️Attacks        |
| :-: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------: |
|  1  | <em>Verify:</em> When a user reports an authenticator lost, they should be reauthenticated </br> <em>Reason:</em> Confirm that the actual user is making the lost claim not someone else                                                                                                        |    High    |     `Impersonation`     |
|  2  | <em>Verify:</em> If a user reports a lost authenticator during the verification stage at login, a PIN or token URL strategy from [Reset Password](../UserID-Passwords.md#password-reset) must be followed</br> <em>Reason:</em> Establish a secure way for a user to change their authenticator |    High    | `Impersonation` `Theft` |
|  3  | <em>Verify:</em> After a successful identity check, the website must ask the user to register a new authenticator </br> <em>Reason:</em> Replace the lost authenticator                                                                                                                         |    High    | `Impersonation` `Theft` |
|  4  | <em>Verify:</em> The lost authenticator no longer works with the user's account </br> <em>Reason:</em> Incase an attacker gets a hold of the authenticator, it shouldn't work                                                                                                                   |    High    | `Impersonation` `Theft` |

**🔗 References:**

Open Web Application Security Project (OWASP):

-   <a href="https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v2-authentication" target="_blank">Application Security Verification Checklist - Authentication</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" target="_blank">Authentication Cheat Sheet</a>

National Institute of Standards and Technology (NIST) SP 800-63B:

-   <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#5-authenticator-and-verifier-requirements" target="_blank">5 Authenticator and Verifier Requirements</a>
