# Authenticator Types

This section covers the different types of authentication factors that are available and their security considerations. Each type is divided into the following categories:

| Factor Definition  | Types                                                 | Example                                                                                                                                                                                                                                                                                |
| ------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Something you know | A value that a user remembers                         | [Memorized Secret](#memorized-secrets)                                                                                                                                                                                                                                                 |
| Something you have | The possession of a unique value                      | [lookup Secrets](#lookup-secrets), [Out-of-Band Devices](#out-of-band-devices), [Single and Multi Factor OTP Devices](#single-and-multi-factor-otp-devices) and [Single and Multi-factor Cryptographic Software or Device](#single-and-multi-factor-cryptographic-device-and-software) |
| Something you are  | A physical attribute of a user that is unique to them | [Biometric](#biometric)                                                                                                                                                                                                                                                                |

---

## <ins>Something you know</ins>

### 🧠 Memorized Secrets

🔶 **Definition:** A secret value intended to be chosen and memorized by the user

🔶 **Example:**

-   Passwords
-   Security Questions

**Password**

➡️ Password security checklist can be found [here](../UserID-Password.md)

**Security Questions**

⚠️ Security questions should NOT be used as it is considered RESTRICTED in <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#-5112-memorized-secret-verifiers" target="_blank">NIST SP 800-63B 5.1.1.2</a>

| #️⃣  | ✅Items                                                                                                                                                                                                                                            | ⚠️Severity |        🗡️Attacks         |   🔗Sources   |
| :-: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :-----------: |
|  1  | Verify: Security questions are not used as an authentication factor </br> Reason: Weak form of authentication as the value can be easily guessed                                                                                                   |    High    |      `Bruteforcing`      | [SQCS](#SQCS) |
|  2  | Verify: Simple answers such as '123' are restricted </br> Reason: Easily guessable value                                                                                                                                                           |    High    |      `Bruteforcing`      | [SQCS](#SQCS) |
|  3  | Verify: The user is required to reauthenticate when updating security questions </br> Reason: Ensure that the request is coming from the intended user                                                                                             |    High    |     `Impersonation`      | [SQCS](#SQCS) |
|  4  | Verify: More than one question is asked to increase complexity </br> Reason: Makes guessing harder                                                                                                                                                 |    High    |      `Bruteforcing`      | [SQCS](#SQCS) |
|  5  | Verify: Questions that are being asked are specific to each user instead of generic questions </br> Reason: Generic questions have generic answers and are easily guessable                                                                        |    High    |      `Bruteforcing`      | [SQCS](#SQCS) |
|  6  | Verify: Security questions are presented after when the username and password are accepted </br> Reason: Security questions should only be used as a sector factor because it's not as strong as passwords                                         |    High    |      `Bruteforcing`      | [SQCS](#SQCS) |
|  7  | Verify: Security questions are hashed when stored in the database and must follow the [Credential Storage](../UserID-Password.md#credential-storage) guidelines</br> Reason: In case answers leak, the hash value won't allow access to an account |    High    | `Impersonation`, `Theft` | [SQCS](#SQCS) |

---

## <ins>Something you have</ins>

### 📖 Lookup Secrets

🔶 **Definition:** lookup secrets are a set of secrets shared between the user and a website

🔶 **Example:** Acts as a recovery/backup codes when the user forgets their password or locks their account

| #️⃣  | ✅Items                                                                                                                                                                                                                                                    | ⚠️Severity |                🗡️Attacks                 |        🔗Sources        |
| :-: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :--------------------------------------: | :---------------------: |
|  1  | Verify: lookup secret has at least 112 bits of entropy </br> Reason: Minimum randomness that makes guessing challenging                                                                                                                                    |    High    |              `Bruteforcing`              | [SP800-63B](#SP800-63B) |
|  2  | Verify: Verifier retains only a hashed version of the lookup secrets which follow the [Credential Storage](../UserID-Password.md#credential-storage) guidelines </br> Reason: In case lookup secret leaks, the hash value won't allow access to an account |    High    | `Bruteforcing`, `Impersonation`, `Theft` | [SP800-63B](#SP800-63B) |
|  3  | Verify: If entropy is less than 112 bit, the lookup secret is hashed with a salt that's of a 32 bit length </br> Reason: Compensate lower entropy with a salt which will increase entropy                                                                  |    High    |              `Bruteforcing`              | [SP800-63B](#SP800-63B) |
|  4  | Verify: If the the lookup secret's entropy is less than 64 bits, rate limiting mechanisms shall be put in place </br> Reason: Additional prevention against guessing to compensate for lower entropy                                                       |    High    |              `Bruteforcing`              | [SP800-63B](#SP800-63B) |
|  5  | Verify: lookup secret is accepted only once </br> Reason: Prevent a value from being used more than once in case it leaks                                                                                                                                  |    High    |             `Replay Attack`              | [SP800-63B](#SP800-63B) |
|  6  | Verify: The user is required to reauthenticate with two factors when requesting new lookup secrets </br> Reason: Ensure that the actual user is making a change, not someone else                                                                          |    High    |         `Impersonation`, `Theft`         | [SP800-63B](#SP800-63B) |
|  7  | Verify: Once new lookup secrets are generated, older ones are no longer relevant </br> Reason: Prevent reuse in case of theft                                                                                                                              |    High    |                 `Theft`                  | [SP800-63B](#SP800-63B) |

---

### 📱 Out-of-Band Devices

🔶 **Definition:** Secure out-of-band authenticators are physical devices that can communicate with the verifier over a secure
secondary channel

🔶 **Example:**

-   Push notifications to mobile devices for authentication
-   SMS or phone call to deliver an authentication code

⚠️ OTP delivered through SMS or phone is not secure and is considered RESTRICTED in <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#-5133-authentication-using-the-public-switched-telephone-network" target="_blank">NIST SP800-63B 5.1.3.3</a>

| #️⃣  | ✅Items                                                                                                                                                                                                                                                | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: Phone and SMS should not be used as out-of-band verifiers </br> Reason: Considered as a restricted category by NIST                                                                                                                            |    High    | `Theft`, `Impersonation` | [SP800-63B](#SP800-63B) |
|  2  | Verify: The out-of-band verifier expires requests, codes, or tokens after 10 minutes </br> Reason: Verifier not receiving the code within 10 minutes indicates an issue, such as non-delivery or wrong recipient                                       |    High    |         `Theft`          | [SP800-63B](#SP800-63B) |
|  3  | Verify: Authentication secrets, codes, or tokens are single-use and valid only for the initial authentication request </br> Reason: Prevent reuse in case of theft                                                                                     |    High    | `Theft`, `Impersonation` | [SP800-63B](#SP800-63B) |
|  4  | Verify: Verifier retains only a hashed version of the authentication code, which follow the [Credential Storage](../UserID-Password.md#credential-storage) guidelines</br> Reason: In case code leaks, the hash value won't allow access to an account |    High    | `Theft`, `Impersonation` | [SP800-63B](#SP800-63B) |
|  5  | Verify: Authentication code is generated by a secure random number generator containing at least 20 bits of entropy (typically, a six digital random number is sufficient) </br> Reason: Minimum complexity to make guessing challenging               |    High    |      `Bruteforcing`      | [SP800-63B](#SP800-63B) |

---

### 🔢 Single and Multi Factor OTP Devices

🔶 **Definition:**

-   Single-factor One time Password (OTP) devices are physical devices that generate OTPs
-   Multi-factor OTP devices are like single-factor ones but require activation through either knowledge, physical characteristic, or a combination of both

🔶 **Example:** OTP is displayed on the device and manually entered for transmission to the verifier, demonstrating possession and control. An OTP device can show, for instance, six characters at once

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                        | ⚠️Severity |                 🗡️Attacks                 |        🔗Sources        |
| :-: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :---------------------------------------: | :---------------------: |
|  1  | Verify: Approved cryptography is used to generate the secret </br> Reason: Weak cryptography can be bypassed                                                                                                                                                                   |    High    |              `Bruteforcing`               | [SP800-63B](#SP800-63B) |
|  2  | Verify: Approved authenticated protected channels are used when collecting the OTP </br> Reason: Ensures that the OTP is being generated from the right device                                                                                                                 |    High    |              `Eavesdropping`              | [SP800-63B](#SP800-63B) |
|  3  | Verify: Time-based OTPs expiration is in place </br> Reason: Prevents the OTP from being reused in case its stolen                                                                                                                                                             |    High    | `Theft`, `Impersonation`, `Replay Attack` | [SP800-63B](#SP800-63B) |
|  4  | Verify: Time-based OTP is used only once within the validity period </br> Reason: Prevents the OTP from being reused in case it's stolen                                                                                                                                       |    High    | `Theft` `Impersonation`, `Replay Attack`  | [SP800-63B](#SP800-63B) |
|  5  | Verify: Symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system-based key storage </br> Reason: Key theft can allow an attacker to generate a valid secrets                                  |    High    |         `Theft`, `Impersonation`          | [SP800-63B](#SP800-63B) |
|  6  | Verify: Physical single-factor OTP generator can be revoked in case of theft or loss. Ensure that revocation is immediately effective across logged-in sessions, regardless of location </br> Reason: Protect the user's account from unauthorized access by a malicious party |    High    | `Theft`, `Impersonation`, `Replay Attack` | [SP800-63B](#SP800-63B) |
|  7  | Verify: Verifier can identify the authenticator as a multi-factor device, but in its absence, it should be considered as single-factor </br> Reason: Ensures that a user is choosing the right authentication factor                                                           |    High    |          `Theft`, `Bruteforcing`          | [SP800-63B](#SP800-63B) |

---

### 🔑 Single and Multi Factor Cryptographic Device and Software

🔶 **Definitions:**

-   A single-factor cryptographic device is a hardware device that performs cryptographic operations using a protected cryptographic key(s) and provides the authenticator output via direct connection to the user endpoint
-   A multi-factor cryptographic device is similar to a single-factor cryptographic device but must be activated by either something you know, something you are or both
-   A single-factor cryptographic software is a cryptographic key stored on a disk or some other "soft" media. Authentication is accomplished by proving possession and control of the key
-   A Multi-factor cryptographic software is similar to single-factor cryptographic software but must be activated by either something you know, something you are or both

🔶 **Examples:**

-   Single/Multi-factor cryptographic device:

    -   USB authenticators such as a YubiKey or Google Titan
    -   Smart cards with an embedded processor

-   Single/Multi-factor cryptographic software:

    -   Use of a client X.509 certificate

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                                                                                      | ⚠️Severity |        🗡️Attacks         |        🔗Sources        |
| :-: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :----------------------: | :---------------------: |
|  1  | Verify: Cryptographic keys are highly protected </br> Reason: Key theft can allow an attacker to generate valid secrets                                                                                                                                                                                                                      |    High    | `Theft`, `Impersonation` | [SP800-63B](#SP800-63B) |
|  2  | Verify: Single-factor cryptographic device verifiers generate a challenge nonce, send it to the corresponding authenticator, and use the authenticator output to verify possession of the device. Ensure that the challenge nonce is at least 64 bits in length </br> Reason: The minimum length that makes predicting its value challenging |    High    |      `Bruteforcing`      | [SP800-63B](#SP800-63B) |
|  3  | Verify: Challenge nonce is unique for each authenticator </br> Reason: Ensures that more than one authenticator are not used for a single user account                                                                                                                                                                                       |    High    |     `Impersonation`      | [SP800-63B](#SP800-63B) |
|  4  | Verify: Approved cryptographic algorithms are used in the generation, seeding, and verification </br> Reason: Unauthorized algorithms can be circumvented                                                                                                                                                                                    |    High    |      `Bruteforcing`      | [SP800-63B](#SP800-63B) |

---

## <ins>Something you are</ins>

### 🧬 Biometric

🔶 **Definition:** The use of biometrics in authentication includes both measurements of physical characteristics and behavioral characteristics of a user

🔶 **Example:**

-   Facial recognition
-   Fingerprint scan
-   Iris scan
-   Typing cadence

| #️⃣  | ✅Items                                                                                                                                                                                                                                                                                 | ⚠️Severity |    🗡️Attacks    |        🔗Sources        |
| :-: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------: | :-------------: | :---------------------: |
|  1  | Verify: Biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know </br> Reason: The false match rate in Biometric isn't strong enough to be used as a single factor                                    |    High    | `Impersonation` | [SP800-63B](#SP800-63B) |
|  2  | Verify: The sensor or endpoint is authenticated before capturing the biometric sample from the user </br> Reason: Prevent the use of fraudulent devices                                                                                                                                 |    High    | `Impersonation` | [SP800-63B](#SP800-63B) |
|  3  | Verify: The biometric system allows no more than five consecutive failed authentication attempts </br> Reason: Limit the occurrence of impersonation attacks                                                                                                                            |    High    | `Impersonation` | [SP800-63B](#SP800-63B) |
|  4  | Verify: After five consecutive failed attempts, disable authentication for 30 seconds before the next attempt and increase exponentially with each successive failed attempt or disable the biometric user authentication and offer another factor </br> Reason: Limit guessing attacks |    High    | `Bruteforcing`  | [SP800-63B](#SP800-63B) |
|  5  | Verify: The integrity of the endpoint or sensor can be determined so any sensor or endpoint change can be detected </br> Reason: Prevent an attacker from installing a fraudulent device to bypass biometric check                                                                      |    High    | `Impersonation` | [SP800-63B](#SP800-63B) |

---

**🔗 Sources:**

Open Web Application Security Project (OWASP):

-   <a href="https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html" target="_blank" id="SQCS">[SQCS] Security Question Cheat Sheet</a>

National Institute of Standards and Technology (NIST) SP 800-63B:

-   <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#5-authenticator-and-verifier-requirements" target="_blank" id="SP800-63B">[SP800-63B] 5 Authenticator and Verifier Requirements</a>
