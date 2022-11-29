---
hide:
    - footer
---

# User ID and Password Authentication

## 🪪 User ID

Following two checklists must be considered for the identifiers that can be used as a User ID.

📝 **Username Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                          |                                         ⚠️Severity                                         |                         🗡️Attacks                          |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------: | :--------------------------------------------------------: |
|  1  | <em>Verify:</em> Usernames are case insensitive </br> <em>Reason:</em> Prevent confusion between 'smith' and 'Smith'                                                             | <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px; ">Low </span> | `Impersonation` <span style="opacity:0">`xxxxxxxxxx`</div> |
|  2  | <em>Verify:</em> Usernames are unique </br> <em>Reason:</em> Prevent a username to be used for multiple accounts                                                                 | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>  |                      `Impersonation`                       |
|  3  | <em>Verify:</em> Usernames must be at least 6 characters long </br> <em>Reason:</em> Protection against guessing                                                                 | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>  |                       `Bruteforcing`                       |
|  4  | <em>Verify:</em> Usernames are not same as some system reserved names such as root, admin, administrator etc. </br> <em>Reason:</em> Prevent user from receiving high privileges | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>  |                      `Impersonation`                       |

📝 **Email Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                              |                                          ⚠️Severity                                           |                       🗡️Attacks                       |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------: | :---------------------------------------------------: |
|  1  | <em>Verify:</em> Emails are no longer than 254 characters in length </br> <em>Reason:</em> Protection against denial of service                                                                                      | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> | `DoS` <span style="opacity:0">`xxxxxxxxxxxxxxx`</div> |
|  2  | <em>Verify:</em> Email receives a PIN for verification. The [PIN Security Checklist](#forgot-password) under [Forgot Password](#forgot-password) must be used for this </br> <em>Reason:</em> Verify user's identity |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                    `Impersonation`                    |
|  3  | <em>Verify:</em> Emails are unique </br> <em>Reason:</em> Prevent an email to be used for another account                                                                                                            |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                    `Impersonation`                    |

## 🍎 General Password Policies

Following items must be considered during authentication regardless of the type of protocol or authenticator being used.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                            |                                        ⚠️Severity                                         |         🗡️Attacks          |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------: | :------------------------: |
|  1  | <em>Verify:</em> All authentication related events must be logged. Such as account lockout, account creation, account login etc. </br> <em>Reason:</em> Trigger alerts when abnormal events occur. Also, helps with investigations | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |   `Insufficiant Logging`   |
|  2  | <em>Verify:</em> All user supplied input i.e. passwords, usernames, PINs etc., should never be trusted and must be validated </br> <em>Reason:</em> Protect against injection or Denial of Service (DOS) attacks                   | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> | `SQLi` `LDAPi` `XSS` `DoS` |
|  3  | <em>Verify:</em> TLS (HTTPS) and `Strict-Transport-Security` header is enable for every authentication process </br> <em>Reason:</em> Network traffic is encrypted which helps prevention against eavesdropping                    | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |      `Eavesdropping`       |
|  4  | <em>Verify:</em> Rate limiting mechanisms exist </br> <em>Reason:</em> Prevention against guessing and DoS                                                                                                                         | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |    `Bruteforing` `DoS`     |

## 🔨 Password Registration

Following items must be considered for the user registration process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                  |                                          ⚠️Severity                                           |                        🗡️Attacks                        |
| :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------: | :-----------------------------------------------------: |
|  1  | <em>Verify:</em> A password is at least 8 characters in length </br> <em>Reason:</em> Protect against guessing since shorter passwords can be guessed                                                    |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   | `Bruteforcing` <span style="opacity:0">`xxxxxxxx`</div> |
|  2  | <em>Verify:</em> A password's maximum length is at least 64 characters </br> <em>Reason:</em> Protect against password length DoS attacks                                                                |  <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px; ">Low </span>   |                          `DoS`                          |
|  3  | <em>Verify:</em> All ASCCI characters, unicodes and white spaces are considered valid input </br> <em>Reason:</em> Allow user to create a complex password which will make it hard to guess              | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Bruteforcing`                      |
|  4  | <em>Verify:</em> Common or previously breached passwords are blocked </br> <em>Reason:</em> Protect against password guessing                                                                            | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Bruteforcing`                      |
|  5  | <em>Verify:</em> Reuse of old passwords is not allowed </br> <em>Reason:</em> Users are likely to use the same password across many websites which can be a risk if one of those websites is compromised |  <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px; ">Low </span>   |                     `Bruteforcing`                      |
|  6  | <em>Verify:</em> The user is not asked to set password hints</br> <em>Reason:</em> Reveals information about the password which makes it easier to guess                                                 |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                     `Bruteforcing`                      |
|  7  | <em>Verify:</em> The user is notified of an account setup via email </br> <em>Reason:</em> The user is aware of the use of their email on an external website                                            | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Impersonation`                     |

## 🚦Password Verification

Following items must be considered for password verification process

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                                          |                                              ⚠️Severity                                              |                        🗡️Attacks                        |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------: | :-----------------------------------------------------: |
|  1  | <em>Verify:</em> If account lockout is in place for the provided email authentication process should not even start </br> <em>Reason:</em> Response time delays during authentication can reveal if an account exist in the database or not      |    <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span>     | `Bruteforcing` <span style="opacity:0">`xxxxxxxx`</div> |
|  2  | <em>Verify:</em> Error responses for failed login attempts are generic such as: <em>username or password is incorrect</em> </br> <em>Reason:</em> Too specific error messages can reveal information about user's account                        |    <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span>     |                     `Bruteforcing`                      |
|  3  | <em>Verify:</em> Response time for username and password checks during authentication should be the same </br> <em>Reason:</em> Difference in response time can indicate if the one of the provided credentials was found in the database or not |    <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span>     |                     `Bruteforcing`                      |
|  4  | <em>Verify:</em> HTTP status codes during authentication are generic </br> <em>Reason:</em> Too specific error messages can reveal information about user's account                                                                              | <span style="background-color:#4097c2; border-radius: 3px; padding: 2px 3px; ">Informational </span> |                     `Bruteforcing`                      |
|  5  | <em>Verify:</em> The `secure` flag is set for all authentication cookies </br> <em>Reason:</em> Authentication cookie value is encrypted                                                                                                         |      <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>       |                  `Eavesdropping` `XSS`                  |
|  6  | <em>Verify:</em> Sensitive cookie data that is related to authentication is not being cached </br> <em>Reason:</em> Someone else can have access incase a device is left unattended or it gets stolen                                            |      <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px; ">Low </span>      |                 `Impersonation` `Theft`                 |
|  7  | <em>Verify:</em> An account is locked after a certain number of failed attempts </br> <em>Reason:</em> Rate limiting mechanism to prevent guessing                                                                                               |      <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>       |                     `Bruteforcing`                      |
|  8  | <em>Verify:</em> User is notified via email when an account lockout takes place </br> <em>Reason:</em> The user must be aware if someone tried to guess their account so they can change their password                                          |      <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>       |                     `Bruteforcing`                      |
|  9  | <em>Verify:</em> Account lockout is not for a fixed time rather it should increase exponentially with each failed login attempt </br> <em>Reason:</em> Rate limiting mechanism that makes it challenging for guessing attacks to occur           |    <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span>     |                     `Bruteforcing`                      |
| 10  | <em>Verify:</em> User is send an email notification if login occurs from a different browser, device, IP or geo location </br> <em>Reason:</em> Incase someone else logged into user's account without their consent                             |      <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px; ">Low </span>      |                     `Impersonation`                     |

## 📦 Password Storage

Following items must be implemented for password storage process

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                  |                                        ⚠️Severity                                         |               🗡️Attacks                |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------: | :------------------------------------: |
|  1  | <em>Verify:</em> Passwords are hashed before storing in the database </br> <em>Reason:</em> Incase of password leak, the hashed passwords won't allow access to an account                                               | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> | `SQLi` `LDAPi` `Theft` `Impersonation` |
|  2  | <em>Verify:</em> Only approved hashing algorithms are used </br> <em>Reason:</em> Unapproved hashing algorithms are insecure since they can be bypassed and clear text values can be extracted                           | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  3  | <em>Verify:</em> A salt is used before hashing passwords </br> <em>Reason:</em> Makes passwords even more complex by adding additional characters to it. Also helps make same passwords used by multiple users different | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  4  | <em>Verify:</em> A salt is at least 32 bits in size </br> <em>Reason:</em> Makes it challenging to be guessed                                                                                                            | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  5  | <em>Verify:</em> Salt is unique for each password </br> <em>Reason:</em> When two users choose the same password, their hash won't be the same as each password is appended to a unique salt                             | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  6  | <em>Verify:</em> Salt is generated by using secure random algorithms </br> <em>Reason:</em> Makes is hard to predict the value of the hash                                                                               | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  7  | <em>Verify:</em> Peppering can be used in addition to salting </br> <em>Reason:</em> Adds additional security to the passwords. Preferred for sensitive accounts                                                         | <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px;">Low </span> |             `Bruteforcing`             |
|  8  | <em>Verify:</em> If peppering is used, it is stored in a password vault </br> <em>Reason:</em> Incase of a database or codebase compromise the safe storage of peppering will help prevent password cracking             | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |
|  9  | <em>Verify:</em> Pepper rotation policy is in place </br> <em>Reason:</em> Incase of a leak, rotation policy will force a new pepper to be used                                                                          | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |         `Bruteforcing` `Theft`         |
| 10  | <em>Verify:</em> Pepper is produced by using secure random algorithms </br> <em>Reason:</em> Makes is challenging to predict the value                                                                                   | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |             `Bruteforcing`             |

## 🔃 Password Reset

Following items must be implemented for password reset process.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                               |                                          ⚠️Severity                                           |                        🗡️Attacks                         |
| :-: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------: | :------------------------------------------------------: |
|  1  | <em>Verify:</em> User is required to reauthenticate before a password reset </br> <em>Reason:</em> Ensure that the actual user is making a change not someone else                                    |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   | `Impersonation` <span style="opacity:0">`xxxxxxxx`</div> |
|  2  | <em>Verify:</em> User is required to type the new password twice </br> <em>Reason:</em> Helps prevent typing mistakes mistakes                                                                        | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                            ⛔                            |
|  3  | <em>Verify:</em> Email notification is sent to this user when password change is successful </br> <em>Reason:</em> Incase user did not authorized a password change they should know someone else did | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Impersonation`                      |

!!! Warning "Continue ..."

     Verify that the new password must follows the [Password Registration](#password-registration) checklist

## 😕 Forgot Password

When a user chooses forgot password, this can be done through multiple ways:

-   Generate a PIN which can be sent to the user with the provided email or phone number. This PIN needs to be confirmed before password reset is allowed
-   Create a token and pass it into the query string, create a limited session around that unique URL and send it to the user's email
-   Recovery/Backup codes can also be used to give access when the user can't remember their password.
-   Some application might rely on security questions for password reset

!!! Danger

    Security questions should NOT be used. If your application uses security questions, you can find a checklist to secure them [here](./MFA/Types.md#memorized-secrets)

Following items must be considered for using PINS, URL tokens or Backup Codes.

📝 **PIN Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                                                                    |                                          ⚠️Severity                                           |                        🗡️Attacks                        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------: | :-----------------------------------------------------: |
|  1  | <em>Verify:</em> PIN must be 6 to 12 digits long </br> <em>Reason:</em> Protection against guessing                                                                                                                                                        |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   | `Bruteforcing` <span style="opacity:0">`xxxxxxxx`</div> |
|  2  | <em>Verify:</em> PIN is unique and is generated using secure random algorithms </br> <em>Reason:</em> Protection against guessing since a random value is hard to predict                                                                                  |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                     `Bruteforcing`                      |
|  3  | <em>Verify:</em> PIN must be sent to either email or phone number that the user provided </br> <em>Reason:</em> The possession of the PIN verifies their identity                                                                                          |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                     `Impersonation`                     |
|  4  | <em>Verify:</em> A limited time session is permitted for the PIN until it expires </br> <em>Reason:</em> Incase the PIN leaks through an email/phone compromise, it no longer active after a few minutes                                                   |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                 `Impersonation` `Theft`                 |
|  5  | <em>Verify:</em> Use [Password Storage](#password-storage) policies for hashing the PIN when its being stored </br> <em>Reason:</em> Helps against database compromise or PIN leakage                                                                      |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                         `Theft`                         |
|  6  | <em>Verify:</em> A generic message is shown if the email provided exists or not such as: "A PIN is sent to the provided email if it exists in the database" </br> <em>Reason:</em> Too specific error messages can reveal information about user's account | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Bruteforcing`                      |
|  7  | <em>Verify:</em> PIN is checked for validity before the user is able to set the set a new password </br> <em>Reason:</em> Likelihood of a logic error is high when PIN validity check and password reset happens together                                  |   <span style="background-color:#6e9642; border-radius: 3px; padding: 2px 3px;">Low </span>   |              `Logic Error` `Impersonation`              |
|  8  | <em>Verify:</em> PIN in invalidated once it has been used </br> <em>Reason:</em> Prevent the reuse of the PIN                                                                                                                                              |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                 `Impersonation` `Theft`                 |

📝 **URL Token Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                    |                                          ⚠️Severity                                           |                         🗡️Attacks                          |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------: | :--------------------------------------------------------: |
|  1  | <em>Verify:</em> Token is generated using secure random algorithms </br> <em>Reason:</em> Protection against guessing since a random value is hard to predict                                              |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   | `Bruteforcing` <span style="opacity:0">`xxxxxxxxxxx`</div> |
|  2  | <em>Verify:</em> Use [Password Storage](#password-storage) policies for hashing the token when its being stored </br> <em>Reason:</em> Helps against database compromise or token leakage                  |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                          `Theft`                           |
|  3  | <em>Verify:</em> URL is hard-coded rather that relying on host header </br> <em>Reason:</em> Protection against host header injection                                                                      | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                           `HHi`                            |
|  4  | <em>Verify:</em> The reset password page uses Referrer Policy tag with the `noreferrer` value </br> <em>Reason:</em> Prevention against referrer leakage                                                   | <span style="background-color:#ad8c07; border-radius: 3px; padding: 2px 3px; ">Medium </span> |                     `Referrer Leakage`                     |
|  5  | <em>Verify:</em> A limited session is allowed for the URL token before it expires </br> <em>Reason:</em> Incase the token leaks through an email/phone compromise, it no longer active after a few minutes |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                  `Impersonation` `Theft`                   |
|  6  | <em>Verify:</em> Token is checked for validity before the user is able to set the set a new password </br> <em>Reason:</em> Ensure that request is coming from the intended user                           |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                      `Impersonation`                       |
|  7  | <em>Verify:</em> Token in invalidated once it has been used </br> <em>Reason:</em> Prevent the reuse of the token                                                                                          |   <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span>   |                  `Impersonation` `Theft`                   |

📝 **Recovery/Backup Code Security Checklist:**

Recovery/Backup code security checklist can be viewed [here](./MFA/Types.md#look-up-secrets)

!!! Warning "Continue ..."

    Once the user has been confirmed, then [Password Reset](#password-reset) checklist must be used to check functionality for the reset process

## 📜 Additional Password Policies

Following items must also be considered.

📝 **Security Checklist:**

| #️⃣  | ✅Items                                                                                                                                                                                                             |                                        ⚠️Severity                                         |        🗡️Attacks        |
| :-: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------: | :---------------------: |
|  1  | <em>Verify:</em> Password expiration is in place </br> <em>Reason:</em> Incase password leaks it is no longer active forever                                                                                        | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> | `Impersonation` `Theft` |
|  2  | <em>Verify:</em> Application requires the user to reauthenticate for sensitive features such as payment, updating password or email etc.</br> <em>Reason:</em> Ensure that request is coming from the intended user | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |     `Impersonation`     |
|  3  | <em>Verify:</em> User has the option to set a second or multi factor authentication </br> <em>Reason:</em> Password leak won't impact because the second factor is still not compromised                            | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> | `Impersonation` `Theft` |
|  4  | <em>Verify:</em> Reauthentication takes places after a period of inactivity </br> <em>Reason:</em> Someone else cant use a user's device if it is left unattended or forgot to logout                               | <span style="background-color:#de3a3c; border-radius: 3px; padding: 2px 3px">High </span> |     `Impersonation`     |

**🔗 References:**

Open Web Application Security Project (OWASP):

-   <a href="https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v2-authentication" target="_blank">Application Security Verification Checklist - Authentication</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" target="_blank">Authentication Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" target="_blank">Password Storage Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html" target="_blank">Forgot Password Cheat Sheet</a>
-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" target="_blank">Input Validation Cheat Sheet</a>

National Institute of Standards and Technology (NIST) SP 800-63B:

-   <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#-5112-memorized-secret-verifiers" target="_blank">5.1.1.2 Memorized Secret Verifiers</a>
