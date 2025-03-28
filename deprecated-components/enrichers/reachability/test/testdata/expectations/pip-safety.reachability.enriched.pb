
Êá
ø¢€·Ø’Ó‰
pip-safetyª
pkg:pypi/requestsVulnerable Dependencyrequests[>=0,<=1.2.3]0:ÛAdvisory: Specific versions of Requests are susceptible to a Denial of Service (DoS) attack. This vulnerability is triggered when an incorrect password is sent in a digest authentication request, causing the library to indefinitely retry the request. Such behavior can be exploited by an attacker to send numerous requests, leading to a service outage by overwhelming the system's resources.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65531/97cBunknown•
pkg:pypi/requestsVulnerable Dependencyrequests[<=2.19.1]0:¹Advisory: Requests before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36546/97cBunknownJCVE-2018-18074¨
pkg:pypi/requestsVulnerable Dependencyrequests[<2.3.0]0:ÏAdvisory: Requests before 2.3.0 exposes Authorization or Proxy-Authorization headers on redirect. This fixes CVE-2014-1830.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39575/97cBunknownJCVE-2014-1830¢
pkg:pypi/requestsVulnerable Dependencyrequests[<2.3.0]0:ÉAdvisory: Requests before 2.3.0 exposes Authorization or Proxy-Authorization headers on redirect. See: CVE-2014-1829.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/26101/97cBunknownJCVE-2014-1829Ö
pkg:pypi/requestsVulnerable Dependencyrequests[>=2.3.0,<2.31.0]0:óAdvisory: Requests 2.31.0 includes a fix for CVE-2023-32681: Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use 'rebuild_proxies' to reattach the 'Proxy-Authorization' header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the 'Proxy-Authorization' header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/58755/97cBunknownJCVE-2023-32681ø
pkg:pypi/requestsVulnerable Dependencyrequests[>=2.1,<=2.5.3]0:˜Advisory: The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/26103/97cBunknownJCVE-2015-2296±
pkg:pypi/requestsVulnerable Dependencyrequests[<2.32.2]0:ÖAdvisory: Affected versions of Requests, when making requests through a Requests `Session`, if the first request is made with `verify=False` to disable cert verification, all subsequent requests to the same host will continue to ignore cert verification regardless of changes to the value of `verify`. This behavior will continue for the lifecycle of the connection in the connection pool. Requests 2.32.0 fixes the issue, but versions 2.32.0 and 2.32.1 were yanked due to conflicts with CVE-2024-35195 mitigation.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71064/97cBunknownJCVE-2024-35195ö
pkg:pypi/requestsVulnerable Dependencyrequests[<=0.13.1]0:ªAdvisory: If an incorrect password is used in conjunction with digest authentication in the `requests` package, it can lead to an infinite request retry cycle. This presents a Denial of Service (DoS) vulnerability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61879/97cBunknownÚ
pkg:pypi/cryptographyVulnerable Dependencycryptography[<=3.2]0:ùAdvisory: Cryptography 3.2 and prior are vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38932/97cBunknownJCVE-2020-25659 
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.5]0:ÍAdvisory: Cryptography version 42.0.5 introduces a limit on the number of name constraint checks during X.509 path validation to prevent denial of service attacks.
https://github.com/pyca/cryptography/commit/4be53bf20cc90cbac01f5f94c5d1aecc5289ba1f
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65647/97cBunknown¿
pkg:pypi/cryptographyVulnerable Dependencycryptography[<1.5.3]0:ŞAdvisory: Cryptography 1.5.3 includes a fix for CVE-2016-9243: HKDF in cryptography before 1.5.2 returns an empty byte-string if used with a length less than algorithm.digest_size.
https://github.com/pyca/cryptography/commit/b924696b2e8731f39696584d12cceeb3aeb2d874
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25680/97cBunknownJCVE-2016-9243
pkg:pypi/cryptographyVulnerable Dependencycryptography[<3.3.2]0:¼Advisory: Cryptography 3.3.2 includes a fix for CVE-2020-36242: certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39606/97cBunknownJCVE-2020-36242Œ	
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.8]0:ªAdvisory: The `cryptography` library has updated its BoringSSL and OpenSSL dependencies in CI due to a security concern. Specifically, the issue involves the functions `EVP_PKEY_param_check()` and `EVP_PKEY_public_check()`, which are used to check DSA public keys or parameters. These functions can experience significant delays when processing excessively long DSA keys or parameters, potentially leading to a Denial of Service (DoS) if the input is from an untrusted source. The vulnerability arises because the key and parameter check functions do not limit the modulus size during checks, despite OpenSSL not allowing public keys with a modulus over 10,000 bits for signature verification. This issue affects applications that directly call these functions and the OpenSSL `pkey` and `pkeyparam` command-line applications with the `-check` option. The OpenSSL SSL/TLS implementation is not impacted, but the OpenSSL 3.0 and 3.1 FIPS providers are affected by this vulnerability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71681/97cBunknownJCVE-2024-4603÷
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=1.9.0,<2.3]0:Advisory: A flaw was found in python-cryptography versions between >=1.9.0 and <2.3. The finalize_with_tag API did not enforce a minimum tag length. If a user did not validate the input length prior to passing it to finalize_with_tag an attacker could craft an invalid payload with a shortened tag (e.g. 1 byte) such that they would have a 1 in 256 chance of passing the MAC check. GCM tag forgeries can cause key leakage. See: CVE-2018-10903.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36351/97cBunknownJCVE-2018-10903¡
pkg:pypi/cryptographyVulnerable Dependencycryptography[<3.3]0:ÑAdvisory: Cryptography 3.3 no longer allows loading of finite field Diffie-Hellman parameters of less than 512 bits in length. This change is to conform with an upcoming OpenSSL release that no longer supports smaller sizes. These keys were already wildly insecure and should not have been used in any application outside of testing.
https://github.com/pyca/cryptography/pull/5592
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39252/97cBunknownœ
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=3.1,<41.0.6]0:³Advisory: Affected versions of Cryptography are vulnerable to NULL-dereference when loading PKCS7 certificates. Calling 'load_pem_pkcs7_certificates' or 'load_der_pkcs7_certificates' could lead to a NULL-pointer dereference and segfault. Exploitation of this vulnerability poses a serious risk of Denial of Service (DoS) for any application attempting to deserialize a PKCS7 blob/certificate. The consequences extend to potential disruptions in system availability and stability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62556/97cBunknownJCVE-2023-49083ï
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.0]0:Advisory: Cryptography 41.0.0 updates its dependency 'OpenSSL' to v3.1.1 to include a security fix.
https://github.com/pyca/cryptography/commit/8708245ccdeaff21d65eea68a4f8d2a7c5949a22
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59062/97cBunknownJCVE-2023-2650…
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.0]0:£Advisory: Cryptography starting from version 42.0.0 updates its CI configurations to use newer versions of BoringSSL or OpenSSL as a countermeasure to CVE-2023-5678. This vulnerability, affecting the package, could cause Denial of Service through specific DH key generation and verification functions when given overly long parameters.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65510/97cBunknownJCVE-2023-5678„
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.0]0:¡Advisory: Affected versions of Cryptography may allow a remote attacker to decrypt captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or sensitive data.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65278/97cBunknownJCVE-2023-50782–
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=37.0.0,<38.0.3]0:«Advisory: Cryptography versions from 37.0.0 and before 38.0.2 include a statically linked copy of OpenSSL that has known vulnerabilities.
https://github.com/pyca/cryptography/security/advisories/GHSA-39hc-v87j-747x
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52174/97cBunknownJCVE-2022-3602–
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=37.0.0,<38.0.3]0:«Advisory: Cryptography versions from 37.0.0 and before 38.0.2 include a statically linked copy of OpenSSL that has known vulnerabilities.
https://github.com/pyca/cryptography/security/advisories/GHSA-39hc-v87j-747x
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52173/97cBunknownJCVE-2022-3786„
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0,<1.1]0:°Advisory: Cryptography before 1.1 is susceptible to TLS truncation attacks. This vulnerability allows an attacker to prevent the complete retrieval of a message by injecting a TCP termination code into the communication, falsely indicating the message has ended.
https://github.com/pyca/cryptography/commit/41aabcbd2326ae154a16a1a050ee01fb9a54bd19
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65984/97cBunknown’
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=38.0.0,<42.0.4]0:¦Advisory: cryptography is a package designed to expose cryptographic primitives and recipes to Python developers. Starting in version 38.0.0 and before version 42.0.4, if `pkcs12.serialize_key_and_certificates` is called with both a certificate whose public key did not match the provided private key and an `encryption_algorithm` with `hmac_hash` set (via `PrivateFormat.PKCS12.encryption_builder().hmac_hash(...)`, then a NULL pointer dereference would occur, crashing the Python process. This has been resolved in version 42.0.4, the first version in which a `ValueError` is properly raised.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/66704/97cBunknownJCVE-2024-26130½
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.5]0:ÛAdvisory: Cryptography 41.0.5 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.4, that includes a security fix.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62452/97cBunknownJCVE-2023-5363ú
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.2]0:˜Advisory: The cryptography library has updated its OpenSSL dependency in CI due to security concerns. This vulnerability arises when processing maliciously formatted PKCS12 files, which can cause OpenSSL to crash, leading to a potential Denial of Service (DoS) attack. PKCS12 files, often containing certificates and keys, may come from untrusted sources. The PKCS12 specification allows certain fields to be NULL, but OpenSSL does not correctly handle these cases, resulting in a NULL pointer dereference and subsequent crash. Applications using OpenSSL APIs, such as PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes(), and PKCS12_newpass(), are vulnerable if they process PKCS12 files from untrusted sources. Although a similar issue in SMIME_write_PKCS7() was fixed, it is not considered significant for security as it pertains to data writing. This issue does not affect the FIPS modules in versions 3.2, 3.1, and 3.0.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71680/97cBunknownJCVE-2024-0727Ó
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.6]0:èAdvisory: The `cryptography` library updates its BoringSSL and OpenSSL dependencies in CI due to a security concern. Specifically, certain non-default TLS server configurations can cause unbounded memory growth when processing TLSv1.3 sessions, leading to a potential Denial of Service (DoS) attack. The issue arises when the `SSL_OP_NO_TICKET` option is used without early data support and default anti-replay protection. Under these conditions, the session cache can become misconfigured, preventing it from flushing properly and causing it to grow indefinitely. A malicious client can exploit this scenario to trigger a DoS attack, although it can also occur accidentally during normal operations. This vulnerability affects only TLS servers supporting TLSv1.3 and does not impact TLS clients. Additionally, the FIPS modules in versions 3.2, 3.1, and 3.0, as well as OpenSSL 1.0.2, are not affected by this issue.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71684/97cBunknownJCVE-2024-2511½
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/b22271cf3c3dd8dc8978f8f4b00b5c7060b6538d
https://www.openssl.org/news/secadv/20230731.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60223/97cBunknownJCVE-2023-3817è
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:€Advisory: Cryptography 41.0.3  updates its bundled OpenSSL version to include a fix for CVE-2023-2975: AES-SIV implementation ignores empty associated data entries.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230714.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60224/97cBunknownJCVE-2023-2975½
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230719.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60225/97cBunknownJCVE-2023-3446Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53307/97cBunknownJCVE-2023-0401Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53306/97cBunknownJCVE-2023-0217Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53301/97cBunknownJCVE-2022-4203Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53302/97cBunknownJCVE-2023-0216Î
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:ìAdvisory: Cryptography 39.0.1 includes a fix for CVE-2022-3996, a DoS vulnerability affecting openssl.
https://github.com/pyca/cryptography/issues/7940
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53298/97cBunknownJCVE-2022-3996Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53303/97cBunknownJCVE-2022-4304Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53304/97cBunknownJCVE-2023-0286Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53299/97cBunknownJCVE-2022-4450Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53305/97cBunknownJCVE-2023-0215ª
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.2]0:ÇAdvisory: The cryptography package before 41.0.2 for Python mishandles SSH certificates that have critical options.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59473/97cBunknownJCVE-2023-38325ı
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=1.8,<39.0.1]0:”Advisory: Cryptography 39.0.1 includes a fix for CVE-2023-23931: In affected versions 'Cipher.update_into' would accept Python objects which implement the buffer protocol, but provide only immutable buffers. This would allow immutable objects (such as 'bytes') to be mutated, thus violating fundamental rules of Python and resulting in corrupted output. This issue has been present since 'update_into' was originally introduced in cryptography 1.8.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53048/97cBunknownJCVE-2023-23931“
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.4]0:±Advisory: Cryptography 41.0.4 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.3, that includes a security fix.
https://github.com/pyca/cryptography/commit/fc11bce6930e591ce26a2317b31b9ce2b3e25512
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62451/97cBunknownJCVE-2023-4807¥
pkg:pypi/cryptographyVulnerable Dependencycryptography[<1.0.2]0:ÓAdvisory: Cryptography 1.0.2 fixes a vulnerability. The OpenSSL backend prior to 1.0.2 made extensive use  of assertions to check response codes where our tests could not trigger a  failure.  However, when Python is run with '-O' these asserts are optimized  away.  If a user ran Python with this flag and got an invalid response code, this could lead to undefined behavior or worse.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25679/97cBunknownÁ
pkg:pypi/cryptographyVulnerable Dependencycryptography[<2.1.3]0:àAdvisory: Cryptography 2.1.3 updates Windows, macOS, and manylinux1 wheels to be compiled with OpenSSL 1.1.0g, that includes security fixes.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50724/97cBunknownJCVE-2017-3735Á
pkg:pypi/cryptographyVulnerable Dependencycryptography[<2.1.3]0:àAdvisory: Cryptography 2.1.3 updates Windows, macOS, and manylinux1 wheels to be compiled with OpenSSL 1.1.0g, that includes security fixes.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50725/97cBunknownJCVE-2017-3736Ã
pkg:pypi/cryptographyVulnerable Dependencycryptography[<0.9.1]0:ñAdvisory: Cryptography 0.9.1 fixes a double free in the OpenSSL backend when using DSA  to verify signatures.
https://github.com/pyca/cryptography/pull/2013
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25678/97cBunknowní

pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.2]0:‚
Advisory: Checking excessively long invalid RSA public keys may take a long time. Applications that use the function EVP_PKEY_public_check() to check RSA public keys may experience long delays. Where the key that is being checked has been obtained from an untrusted source this may lead to a Denial of Service. When function EVP_PKEY_public_check() is called on RSA public keys, a computation is done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more large primes and this computation completes quickly. However, if n is an overly large prime, then this computation would take a long time. An application that calls EVP_PKEY_public_check() and supplies an RSA key obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function EVP_PKEY_public_check() is not called from other OpenSSL functions however it is called from the OpenSSL pkey command line application. For that reason that application is also vulnerable if used with the '-pubin' and '-check' options on untrusted data. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/66777/97cBunknownJCVE-2023-6237Ô
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.2]0:éAdvisory: Versions of Cryptograph starting from 35.0.0 are susceptible to a security flaw in the POLY1305 MAC algorithm on PowerPC CPUs, which allows an attacker to disrupt the application's state. This disruption might result in false calculations or cause a denial of service. The vulnerability's exploitation hinges on the attacker's ability to alter the algorithm's application and the dependency of the software on non-volatile XMM registers.
https://github.com/pyca/cryptography/commit/89d0d56fb104ac4e0e6db63d78fc22b8c53d27e9
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65212/97cBunknownJCVE-2023-6129
pkg:pypi/clickVulnerable Dependencyclick[<8.0.0]0:ÙAdvisory: Click 8.0.0 uses 'mkstemp()' instead of the deprecated & insecure 'mktemp()'.
https://github.com/pallets/click/issues/1752
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/47833/97cBunknown©
pkg:pypi/pyjwtVulnerable Dependencypyjwt[<1.0.0]0:åAdvisory: Pyjwt 1.0.0 includes a security fix: 'alg=None' header could bypass signature verification.
https://github.com/jpadilla/pyjwt/pull/109
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39458/97cBunknownÛ
pkg:pypi/pyjwtVulnerable Dependencypyjwt[>=1.5.0,<2.4.0]0:ÿAdvisory: PyJWT 2.4.0 includes a fix for CVE-2022-29217: An attacker submitting the JWT token can choose the used signing algorithm. The PyJWT library requires that the application chooses what algorithms are supported. The application can specify 'jwt.algorithms.get_default_algorithms()' to get support for all algorithms, or specify a single algorithm. The issue is not that big as 'algorithms=jwt.algorithms.get_default_algorithms()' has to be used. As a workaround, always be explicit with the algorithms that are accepted and expected when decoding.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/48542/97cBunknownJCVE-2022-29217€
pkg:pypi/pyjwtVulnerable Dependencypyjwt[<1.5.1]0:¬Advisory: In PyJWT 1.5.0 and below the `invalid_strings` check in `HMACAlgorithm.prepare_key` does not account for all PEM encoded public keys. Specifically, the PKCS1 PEM encoded format would be allowed because it is prefaced with the string `-----BEGIN RSA PUBLIC KEY-----` which is not accounted for. This enables symmetric/asymmetric key confusion attacks against users using the PKCS1 PEM encoded public keys, which would allow an attacker to craft JWTs from scratch.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/35014/97cBunknownJCVE-2017-11424ƒ
pkg:pypi/flaskVulnerable Dependencyflask[<2.2.5 >=2.3.0,<2.3.2]0: 
Advisory: Flask 2.2.5 and 2.3.2 include a fix for CVE-2023-30861: When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches 'Set-Cookie' headers, it may send one client's 'session' cookie to other clients. The severity depends on the application's use of the session and the proxy's behavior regarding cookies. The risk depends on all these conditions being met:
1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets 'session.permanent = True'
3. The application does not access or modify the session at any point during a request.
4. 'SESSION_REFRESH_EACH_REQUEST' enabled (the default).
5. The application does not set a 'Cache-Control' header to indicate that a page is private or should not be cached.
This happens because vulnerable versions of Flask only set the 'Vary: Cookie' header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified.
https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/55261/97cBunknownJCVE-2023-30861É
pkg:pypi/flaskVulnerable Dependencyflask[<0.6.1]0:…Advisory: flask 0.6.1 fixes a security problem that allowed clients to download arbitrary files  if the host server was a windows based operating system and the client  uses backslashes to escape the directory the files where exposed from.
https://data.safetycli.com/vulnerabilities/PVE-2021-25820/25820/
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25820/97cBunknown€
pkg:pypi/flaskVulnerable Dependencyflask[<0.12.3]0:©Advisory: flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36388/97cBunknownJCVE-2018-1000656Ö
pkg:pypi/flaskVulnerable Dependencyflask[<0.12.3]0:ÿAdvisory: Flask 0.12.3 includes a fix for CVE-2019-1010083: Unexpected memory usage. The impact is denial of service. The attack vector is crafted encoded JSON data. NOTE: this may overlap CVE-2018-1000656.
https://github.com/pallets/flask/pull/2695/commits/0e1e9a04aaf29ab78f721cfc79ac2a691f6e3929
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38654/97cBunknownJCVE-2019-1010083Á
ª
pkg:pypi/requestsVulnerable Dependencyrequests[>=0,<=1.2.3]0:ÛAdvisory: Specific versions of Requests are susceptible to a Denial of Service (DoS) attack. This vulnerability is triggered when an incorrect password is sent in a digest authentication request, causing the library to indefinitely retry the request. Such behavior can be exploited by an attacker to send numerous requests, leading to a service outage by overwhelming the system's resources.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65531/97cBunknown:
	reachablefalse¬
•
pkg:pypi/requestsVulnerable Dependencyrequests[<=2.19.1]0:¹Advisory: Requests before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36546/97cBunknownJCVE-2018-18074:
	reachablefalse¿
¨
pkg:pypi/requestsVulnerable Dependencyrequests[<2.3.0]0:ÏAdvisory: Requests before 2.3.0 exposes Authorization or Proxy-Authorization headers on redirect. This fixes CVE-2014-1830.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39575/97cBunknownJCVE-2014-1830:
	reachablefalse¹
¢
pkg:pypi/requestsVulnerable Dependencyrequests[<2.3.0]0:ÉAdvisory: Requests before 2.3.0 exposes Authorization or Proxy-Authorization headers on redirect. See: CVE-2014-1829.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/26101/97cBunknownJCVE-2014-1829:
	reachablefalseí
Ö
pkg:pypi/requestsVulnerable Dependencyrequests[>=2.3.0,<2.31.0]0:óAdvisory: Requests 2.31.0 includes a fix for CVE-2023-32681: Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use 'rebuild_proxies' to reattach the 'Proxy-Authorization' header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the 'Proxy-Authorization' header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/58755/97cBunknownJCVE-2023-32681:
	reachablefalse
ø
pkg:pypi/requestsVulnerable Dependencyrequests[>=2.1,<=2.5.3]0:˜Advisory: The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/26103/97cBunknownJCVE-2015-2296:
	reachablefalseÈ
±
pkg:pypi/requestsVulnerable Dependencyrequests[<2.32.2]0:ÖAdvisory: Affected versions of Requests, when making requests through a Requests `Session`, if the first request is made with `verify=False` to disable cert verification, all subsequent requests to the same host will continue to ignore cert verification regardless of changes to the value of `verify`. This behavior will continue for the lifecycle of the connection in the connection pool. Requests 2.32.0 fixes the issue, but versions 2.32.0 and 2.32.1 were yanked due to conflicts with CVE-2024-35195 mitigation.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71064/97cBunknownJCVE-2024-35195:
	reachablefalse
ö
pkg:pypi/requestsVulnerable Dependencyrequests[<=0.13.1]0:ªAdvisory: If an incorrect password is used in conjunction with digest authentication in the `requests` package, it can lead to an infinite request retry cycle. This presents a Denial of Service (DoS) vulnerability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61879/97cBunknown:
	reachablefalseñ
Ú
pkg:pypi/cryptographyVulnerable Dependencycryptography[<=3.2]0:ùAdvisory: Cryptography 3.2 and prior are vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38932/97cBunknownJCVE-2020-25659:
	reachablefalse·
 
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.5]0:ÍAdvisory: Cryptography version 42.0.5 introduces a limit on the number of name constraint checks during X.509 path validation to prevent denial of service attacks.
https://github.com/pyca/cryptography/commit/4be53bf20cc90cbac01f5f94c5d1aecc5289ba1f
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65647/97cBunknown:
	reachablefalseÖ
¿
pkg:pypi/cryptographyVulnerable Dependencycryptography[<1.5.3]0:ŞAdvisory: Cryptography 1.5.3 includes a fix for CVE-2016-9243: HKDF in cryptography before 1.5.2 returns an empty byte-string if used with a length less than algorithm.digest_size.
https://github.com/pyca/cryptography/commit/b924696b2e8731f39696584d12cceeb3aeb2d874
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25680/97cBunknownJCVE-2016-9243:
	reachablefalseµ

pkg:pypi/cryptographyVulnerable Dependencycryptography[<3.3.2]0:¼Advisory: Cryptography 3.3.2 includes a fix for CVE-2020-36242: certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39606/97cBunknownJCVE-2020-36242:
	reachablefalse£	
Œ	
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.8]0:ªAdvisory: The `cryptography` library has updated its BoringSSL and OpenSSL dependencies in CI due to a security concern. Specifically, the issue involves the functions `EVP_PKEY_param_check()` and `EVP_PKEY_public_check()`, which are used to check DSA public keys or parameters. These functions can experience significant delays when processing excessively long DSA keys or parameters, potentially leading to a Denial of Service (DoS) if the input is from an untrusted source. The vulnerability arises because the key and parameter check functions do not limit the modulus size during checks, despite OpenSSL not allowing public keys with a modulus over 10,000 bits for signature verification. This issue affects applications that directly call these functions and the OpenSSL `pkey` and `pkeyparam` command-line applications with the `-check` option. The OpenSSL SSL/TLS implementation is not impacted, but the OpenSSL 3.0 and 3.1 FIPS providers are affected by this vulnerability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71681/97cBunknownJCVE-2024-4603:
	reachablefalse
÷
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=1.9.0,<2.3]0:Advisory: A flaw was found in python-cryptography versions between >=1.9.0 and <2.3. The finalize_with_tag API did not enforce a minimum tag length. If a user did not validate the input length prior to passing it to finalize_with_tag an attacker could craft an invalid payload with a shortened tag (e.g. 1 byte) such that they would have a 1 in 256 chance of passing the MAC check. GCM tag forgeries can cause key leakage. See: CVE-2018-10903.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36351/97cBunknownJCVE-2018-10903:
	reachablefalse¸
¡
pkg:pypi/cryptographyVulnerable Dependencycryptography[<3.3]0:ÑAdvisory: Cryptography 3.3 no longer allows loading of finite field Diffie-Hellman parameters of less than 512 bits in length. This change is to conform with an upcoming OpenSSL release that no longer supports smaller sizes. These keys were already wildly insecure and should not have been used in any application outside of testing.
https://github.com/pyca/cryptography/pull/5592
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39252/97cBunknown:
	reachablefalse³
œ
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=3.1,<41.0.6]0:³Advisory: Affected versions of Cryptography are vulnerable to NULL-dereference when loading PKCS7 certificates. Calling 'load_pem_pkcs7_certificates' or 'load_der_pkcs7_certificates' could lead to a NULL-pointer dereference and segfault. Exploitation of this vulnerability poses a serious risk of Denial of Service (DoS) for any application attempting to deserialize a PKCS7 blob/certificate. The consequences extend to potential disruptions in system availability and stability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62556/97cBunknownJCVE-2023-49083:
	reachablefalse†
ï
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.0]0:Advisory: Cryptography 41.0.0 updates its dependency 'OpenSSL' to v3.1.1 to include a security fix.
https://github.com/pyca/cryptography/commit/8708245ccdeaff21d65eea68a4f8d2a7c5949a22
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59062/97cBunknownJCVE-2023-2650:
	reachablefalseœ
…
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.0]0:£Advisory: Cryptography starting from version 42.0.0 updates its CI configurations to use newer versions of BoringSSL or OpenSSL as a countermeasure to CVE-2023-5678. This vulnerability, affecting the package, could cause Denial of Service through specific DH key generation and verification functions when given overly long parameters.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65510/97cBunknownJCVE-2023-5678:
	reachablefalse›
„
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.0]0:¡Advisory: Affected versions of Cryptography may allow a remote attacker to decrypt captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or sensitive data.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65278/97cBunknownJCVE-2023-50782:
	reachablefalse­
–
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=37.0.0,<38.0.3]0:«Advisory: Cryptography versions from 37.0.0 and before 38.0.2 include a statically linked copy of OpenSSL that has known vulnerabilities.
https://github.com/pyca/cryptography/security/advisories/GHSA-39hc-v87j-747x
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52174/97cBunknownJCVE-2022-3602:
	reachablefalse­
–
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=37.0.0,<38.0.3]0:«Advisory: Cryptography versions from 37.0.0 and before 38.0.2 include a statically linked copy of OpenSSL that has known vulnerabilities.
https://github.com/pyca/cryptography/security/advisories/GHSA-39hc-v87j-747x
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52173/97cBunknownJCVE-2022-3786:
	reachablefalse›
„
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0,<1.1]0:°Advisory: Cryptography before 1.1 is susceptible to TLS truncation attacks. This vulnerability allows an attacker to prevent the complete retrieval of a message by injecting a TCP termination code into the communication, falsely indicating the message has ended.
https://github.com/pyca/cryptography/commit/41aabcbd2326ae154a16a1a050ee01fb9a54bd19
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65984/97cBunknown:
	reachablefalse©
’
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=38.0.0,<42.0.4]0:¦Advisory: cryptography is a package designed to expose cryptographic primitives and recipes to Python developers. Starting in version 38.0.0 and before version 42.0.4, if `pkcs12.serialize_key_and_certificates` is called with both a certificate whose public key did not match the provided private key and an `encryption_algorithm` with `hmac_hash` set (via `PrivateFormat.PKCS12.encryption_builder().hmac_hash(...)`, then a NULL pointer dereference would occur, crashing the Python process. This has been resolved in version 42.0.4, the first version in which a `ValueError` is properly raised.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/66704/97cBunknownJCVE-2024-26130:
	reachablefalseÔ
½
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.5]0:ÛAdvisory: Cryptography 41.0.5 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.4, that includes a security fix.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62452/97cBunknownJCVE-2023-5363:
	reachablefalse‘	
ú
pkg:pypi/cryptographyVulnerable Dependencycryptography[<42.0.2]0:˜Advisory: The cryptography library has updated its OpenSSL dependency in CI due to security concerns. This vulnerability arises when processing maliciously formatted PKCS12 files, which can cause OpenSSL to crash, leading to a potential Denial of Service (DoS) attack. PKCS12 files, often containing certificates and keys, may come from untrusted sources. The PKCS12 specification allows certain fields to be NULL, but OpenSSL does not correctly handle these cases, resulting in a NULL pointer dereference and subsequent crash. Applications using OpenSSL APIs, such as PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes(), and PKCS12_newpass(), are vulnerable if they process PKCS12 files from untrusted sources. Although a similar issue in SMIME_write_PKCS7() was fixed, it is not considered significant for security as it pertains to data writing. This issue does not affect the FIPS modules in versions 3.2, 3.1, and 3.0.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71680/97cBunknownJCVE-2024-0727:
	reachablefalseê
Ó
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.6]0:èAdvisory: The `cryptography` library updates its BoringSSL and OpenSSL dependencies in CI due to a security concern. Specifically, certain non-default TLS server configurations can cause unbounded memory growth when processing TLSv1.3 sessions, leading to a potential Denial of Service (DoS) attack. The issue arises when the `SSL_OP_NO_TICKET` option is used without early data support and default anti-replay protection. Under these conditions, the session cache can become misconfigured, preventing it from flushing properly and causing it to grow indefinitely. A malicious client can exploit this scenario to trigger a DoS attack, although it can also occur accidentally during normal operations. This vulnerability affects only TLS servers supporting TLSv1.3 and does not impact TLS clients. Additionally, the FIPS modules in versions 3.2, 3.1, and 3.0, as well as OpenSSL 1.0.2, are not affected by this issue.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/71684/97cBunknownJCVE-2024-2511:
	reachablefalseÔ
½
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/b22271cf3c3dd8dc8978f8f4b00b5c7060b6538d
https://www.openssl.org/news/secadv/20230731.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60223/97cBunknownJCVE-2023-3817:
	reachablefalseÿ
è
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:€Advisory: Cryptography 41.0.3  updates its bundled OpenSSL version to include a fix for CVE-2023-2975: AES-SIV implementation ignores empty associated data entries.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230714.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60224/97cBunknownJCVE-2023-2975:
	reachablefalseÔ
½
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230719.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60225/97cBunknownJCVE-2023-3446:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53307/97cBunknownJCVE-2023-0401:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53306/97cBunknownJCVE-2023-0217:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53301/97cBunknownJCVE-2022-4203:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53302/97cBunknownJCVE-2023-0216:
	reachablefalseå
Î
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:ìAdvisory: Cryptography 39.0.1 includes a fix for CVE-2022-3996, a DoS vulnerability affecting openssl.
https://github.com/pyca/cryptography/issues/7940
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53298/97cBunknownJCVE-2022-3996:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53303/97cBunknownJCVE-2022-4304:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53304/97cBunknownJCVE-2023-0286:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53299/97cBunknownJCVE-2022-4450:
	reachablefalseâ
Ë
pkg:pypi/cryptographyVulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53305/97cBunknownJCVE-2023-0215:
	reachablefalseÁ
ª
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.2]0:ÇAdvisory: The cryptography package before 41.0.2 for Python mishandles SSH certificates that have critical options.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59473/97cBunknownJCVE-2023-38325:
	reachablefalse”
ı
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=1.8,<39.0.1]0:”Advisory: Cryptography 39.0.1 includes a fix for CVE-2023-23931: In affected versions 'Cipher.update_into' would accept Python objects which implement the buffer protocol, but provide only immutable buffers. This would allow immutable objects (such as 'bytes') to be mutated, thus violating fundamental rules of Python and resulting in corrupted output. This issue has been present since 'update_into' was originally introduced in cryptography 1.8.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53048/97cBunknownJCVE-2023-23931:
	reachablefalseª
“
pkg:pypi/cryptographyVulnerable Dependencycryptography[<41.0.4]0:±Advisory: Cryptography 41.0.4 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.3, that includes a security fix.
https://github.com/pyca/cryptography/commit/fc11bce6930e591ce26a2317b31b9ce2b3e25512
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62451/97cBunknownJCVE-2023-4807:
	reachablefalse¼
¥
pkg:pypi/cryptographyVulnerable Dependencycryptography[<1.0.2]0:ÓAdvisory: Cryptography 1.0.2 fixes a vulnerability. The OpenSSL backend prior to 1.0.2 made extensive use  of assertions to check response codes where our tests could not trigger a  failure.  However, when Python is run with '-O' these asserts are optimized  away.  If a user ran Python with this flag and got an invalid response code, this could lead to undefined behavior or worse.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25679/97cBunknown:
	reachablefalseØ
Á
pkg:pypi/cryptographyVulnerable Dependencycryptography[<2.1.3]0:àAdvisory: Cryptography 2.1.3 updates Windows, macOS, and manylinux1 wheels to be compiled with OpenSSL 1.1.0g, that includes security fixes.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50724/97cBunknownJCVE-2017-3735:
	reachablefalseØ
Á
pkg:pypi/cryptographyVulnerable Dependencycryptography[<2.1.3]0:àAdvisory: Cryptography 2.1.3 updates Windows, macOS, and manylinux1 wheels to be compiled with OpenSSL 1.1.0g, that includes security fixes.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50725/97cBunknownJCVE-2017-3736:
	reachablefalseÚ
Ã
pkg:pypi/cryptographyVulnerable Dependencycryptography[<0.9.1]0:ñAdvisory: Cryptography 0.9.1 fixes a double free in the OpenSSL backend when using DSA  to verify signatures.
https://github.com/pyca/cryptography/pull/2013
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25678/97cBunknown:
	reachablefalse„
í

pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.2]0:‚
Advisory: Checking excessively long invalid RSA public keys may take a long time. Applications that use the function EVP_PKEY_public_check() to check RSA public keys may experience long delays. Where the key that is being checked has been obtained from an untrusted source this may lead to a Denial of Service. When function EVP_PKEY_public_check() is called on RSA public keys, a computation is done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more large primes and this computation completes quickly. However, if n is an overly large prime, then this computation would take a long time. An application that calls EVP_PKEY_public_check() and supplies an RSA key obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function EVP_PKEY_public_check() is not called from other OpenSSL functions however it is called from the OpenSSL pkey command line application. For that reason that application is also vulnerable if used with the '-pubin' and '-check' options on untrusted data. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/66777/97cBunknownJCVE-2023-6237:
	reachablefalseë
Ô
pkg:pypi/cryptographyVulnerable Dependencycryptography[>=35.0.0,<42.0.2]0:éAdvisory: Versions of Cryptograph starting from 35.0.0 are susceptible to a security flaw in the POLY1305 MAC algorithm on PowerPC CPUs, which allows an attacker to disrupt the application's state. This disruption might result in false calculations or cause a denial of service. The vulnerability's exploitation hinges on the attacker's ability to alter the algorithm's application and the dependency of the software on non-volatile XMM registers.
https://github.com/pyca/cryptography/commit/89d0d56fb104ac4e0e6db63d78fc22b8c53d27e9
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65212/97cBunknownJCVE-2023-6129:
	reachablefalse´

pkg:pypi/clickVulnerable Dependencyclick[<8.0.0]0:ÙAdvisory: Click 8.0.0 uses 'mkstemp()' instead of the deprecated & insecure 'mktemp()'.
https://github.com/pallets/click/issues/1752
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/47833/97cBunknown:
	reachablefalseÀ
©
pkg:pypi/pyjwtVulnerable Dependencypyjwt[<1.0.0]0:åAdvisory: Pyjwt 1.0.0 includes a security fix: 'alg=None' header could bypass signature verification.
https://github.com/jpadilla/pyjwt/pull/109
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39458/97cBunknown:
	reachablefalseò
Û
pkg:pypi/pyjwtVulnerable Dependencypyjwt[>=1.5.0,<2.4.0]0:ÿAdvisory: PyJWT 2.4.0 includes a fix for CVE-2022-29217: An attacker submitting the JWT token can choose the used signing algorithm. The PyJWT library requires that the application chooses what algorithms are supported. The application can specify 'jwt.algorithms.get_default_algorithms()' to get support for all algorithms, or specify a single algorithm. The issue is not that big as 'algorithms=jwt.algorithms.get_default_algorithms()' has to be used. As a workaround, always be explicit with the algorithms that are accepted and expected when decoding.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/48542/97cBunknownJCVE-2022-29217:
	reachablefalse—
€
pkg:pypi/pyjwtVulnerable Dependencypyjwt[<1.5.1]0:¬Advisory: In PyJWT 1.5.0 and below the `invalid_strings` check in `HMACAlgorithm.prepare_key` does not account for all PEM encoded public keys. Specifically, the PKCS1 PEM encoded format would be allowed because it is prefaced with the string `-----BEGIN RSA PUBLIC KEY-----` which is not accounted for. This enables symmetric/asymmetric key confusion attacks against users using the PKCS1 PEM encoded public keys, which would allow an attacker to craft JWTs from scratch.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/35014/97cBunknownJCVE-2017-11424:
	reachablefalseš
ƒ
pkg:pypi/flaskVulnerable Dependencyflask[<2.2.5 >=2.3.0,<2.3.2]0: 
Advisory: Flask 2.2.5 and 2.3.2 include a fix for CVE-2023-30861: When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches 'Set-Cookie' headers, it may send one client's 'session' cookie to other clients. The severity depends on the application's use of the session and the proxy's behavior regarding cookies. The risk depends on all these conditions being met:
1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets 'session.permanent = True'
3. The application does not access or modify the session at any point during a request.
4. 'SESSION_REFRESH_EACH_REQUEST' enabled (the default).
5. The application does not set a 'Cache-Control' header to indicate that a page is private or should not be cached.
This happens because vulnerable versions of Flask only set the 'Vary: Cookie' header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified.
https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/55261/97cBunknownJCVE-2023-30861:
	reachablefalseà
É
pkg:pypi/flaskVulnerable Dependencyflask[<0.6.1]0:…Advisory: flask 0.6.1 fixes a security problem that allowed clients to download arbitrary files  if the host server was a windows based operating system and the client  uses backslashes to escape the directory the files where exposed from.
https://data.safetycli.com/vulnerabilities/PVE-2021-25820/25820/
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/25820/97cBunknown:
	reachablefalse—
€
pkg:pypi/flaskVulnerable Dependencyflask[<0.12.3]0:©Advisory: flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36388/97cBunknownJCVE-2018-1000656:
	reachablefalseí
Ö
pkg:pypi/flaskVulnerable Dependencyflask[<0.12.3]0:ÿAdvisory: Flask 0.12.3 includes a fix for CVE-2019-1010083: Unexpected memory usage. The impact is denial of service. The attack vector is crafted encoded JSON data. NOTE: this may overlap CVE-2018-1000656.
https://github.com/pallets/flask/pull/2695/commits/0e1e9a04aaf29ab78f721cfc79ac2a691f6e3929
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38654/97cBunknownJCVE-2019-1010083:
	reachablefalse