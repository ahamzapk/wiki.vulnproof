Physical Authenticators:

<!-- Credential Service Provider aka CSP -->

Incase of theft the physical authenticator the CSP shall provide a mechanism to revoke or suspend the authenticator immediately when the user notifies the CSP about it

## Rate Limiting

Rate limiting is to prevent an attacker from guessing the secret. Following measures must be taken to prevent that from happening:

-   The maximum number of failed attempts should be no more than 100
-   User is required to complete a CAPTCHA before attempting to authenticate
-   Increase wait time after a few failed attempts as the account approaches the max invalid attempts. The wait time should go up exponentially. Starting from 30 seconds up to an hour.
-   Accepting requests only from white listed IP addresses where the user has authenticated before
-   Use other factors to determine user behavior such as IP addresses, geo location, browser metadata/ID or time of the day when the request is being made

When the subscriber successfully authenticates, the verifier SHOULD disregard any previous failed attempts for that user from the same IP address.

## Attestation

An attestation is information conveyed to the verifier regarding a directly-connected authenticator or the endpoint involved in an authentication operation. Information conveyed by attestation MAY include, but is not limited to:

-   The provenance (e.g., manufacturer or supplier certification), health, and integrity of the authenticator and endpoint.
-   Security features of the authenticator
-   Security and performance characteristics of biometric sensors
-   Sensor functionality
-   Sensor false positive rate or error rate
-   If this attestation is signed, it SHALL be signed using a digital signature that provides at least the minimum security strength of 112 bits

## Verifier Impersonation Resistance

Phishing sites that attempts to fool the user to authenticate. To prevent this following measures must be undertaken:

-   Establish a authenticated protected channel with the verifier
-   It should then attach a value to the authenticator output which is used to prove the authenticators identity to the verifier and hence results in establishing a secure channel. This can be done by signing the value with the authenticator output using a private key that the user controls for which the public key is known to the verifier
-   This is then verified before any authenticator output is accepted
-   Approved cryptographic algorithms must be used to establish verifier impersonation resistance.
-   Cryptographic keys for this signing shall be at least 112 bits in length
-   Authenticators that involve manually entry of the authenticator output such as out of band or OTP authenticators must not considered verifier impersonation resistant because the manual entry does not bind the authenticator output to the specific session being authentication.

## Verifier and Credential Service Provider Communications:

In a situation where the verifier and credential service provider are different, such as using a third party MFA solution such as OKTA or Ping, the following should be considered:

-   Ensure communication between both occurs through manually authenticated secure channel such as a client-authenticated TLS connection
-   Ensure approved cryptography is used for authentication

## Verifier-Compromise Resistance

Authentication protocols that do not require the verifier to persistently store secrets that could be used for authentication are considered strong and are described as verifier compromise resistance. An example of this are the OTP verifiers who independently generate the same output as the authenticator and just compare the value input by the user. Note that these verifiers are not resistant to all attacks.

Verifier compromise resistance can be achieved in different ways:

-   Use a cryptographic authenticator that requires the verifier store a public key corresponding to a private key held by the authenticator.
-   Store the expected authenticator output in hashed form. This method can be used with some look-up secret authenticators
-   Ensure that approved cryptographic algorithms are used
-   Ensure that cryptographic keys are of 112 bits of length minimum

## Replay Resistance

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

Protocols that use nonces or challenges to prove the “freshness” of the transaction are resistant to replay attacks since the verifier will easily detect when old protocol messages are replayed since they will not contain the appropriate nonces or timeliness data

In contrast, memorized secrets are not considered replay resistant because the authenticator output — the secret itself — is provided for each authentication. Meaning that the value remains the same.

## Authentication Intent

An authentication process demonstrates intent if it requires the subject to explicitly respond to each authentication or reauthentication request. The goal of authentication intent is to make it more difficult for directly-connected physical authenticators (e.g., multi-factor cryptographic devices) to be used without the subject’s knowledge, such as by malware on the endpoint.

-   Authentication intent SHALL be established by the authenticator itself, although multi-factor cryptographic devices MAY establish intent by reentry of the other authentication factor on the endpoint with which the authenticator is used
-   Authentication processes that require the subject’s intervention (e.g., a claimant entering an authenticator output from an OTP device) establish intent.
-   Cryptographic devices that require user action (e.g., pushing a button or reinsertion) for each authentication or reauthentication operation are also establish intent.
-   Depending on the modality, presentation of a biometric may or may not establish authentication intent. Presentation of a fingerprint would normally establish intent, while observation of the claimant’s face using a camera normally would not by itself. Behavioral biometrics similarly are less likely to establish authentication intent because they do not always require a specific action on the claimant’s part.

## Restricted Authenticators

If an organization continues to use a restricted authenticator, the following aspect must be considered:

-   What is the level of risk associated with the use of a restricted authenticator
-   Analyze the level of impact incase the authenticator is bypassed
-   If the risk is unacceptable, then the restricted authenticator should not be used
-   What can be done to mitigate the excessive risk
-   Develop a migration plan for the future so that eventually the restricted authenticator is no longer used

If a restricted authenticator factor is being used by customers, following must be notified to them:

-   Risk associated with use of the restricted authenticator factor
-   Provide additional unrestricted authenticators for them to switch to
-   Develop a migration plan for the future so that eventually the restricted authenticator is no longer used
