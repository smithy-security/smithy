
�trivy�
6pkg:apk/alpine/expat@2.2.6-r0?arch=x86_64&distro=3.9.2Container image vulnerabilityu[CVE-2018-20843] expat: large number of colons in input makes parser consume high amount of resources, leading to DoS )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2018-20843
Cwe: CWE-611
Reference: https://avd.aquasec.com/nvd/cve-2018-20843
Original Description:In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be usable for denial-of-service attacks).
Bunknown�
6pkg:apk/alpine/expat@2.2.6-r0?arch=x86_64&distro=3.9.2Container image vulnerabilityI[CVE-2019-15903] expat: heap-based buffer over-read via crafted XML input )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2019-15903
Cwe: CWE-125,CWE-776
Reference: https://avd.aquasec.com/nvd/cve-2019-15903
Original Description:In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then resulted in a heap-based buffer over-read.
Bunknown�
7pkg:apk/alpine/libbz2@1.0.6-r6?arch=x86_64&distro=3.9.2Container image vulnerabilityF[CVE-2019-12900] bzip2: out-of-bounds write in function BZ2_decompress )������#@:�CVSS Score: 9.8
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Cve: CVE-2019-12900
Cwe: CWE-787
Reference: https://avd.aquasec.com/nvd/cve-2019-12900
Original Description:BZ2_decompress in decompress.c in bzip2 through 1.0.6 has an out-of-bounds write when there are many selectors.
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability;[CVE-2019-1543] openssl: ChaCha20-Poly1305 with long nonces )������@:�CVSS Score: 7.4
CvssVector: CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
Cve: CVE-2019-1543
Cwe: CWE-327,CWE-330
Reference: https://avd.aquasec.com/nvd/cve-2019-1543
Original Description:ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input for every encryption operation. RFC 7539 specifies that the nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce length and front pads the nonce with 0 bytes if it is less than 12 bytes. However it also incorrectly allows a nonce to be set of up to 16 bytes. In this case only the last 12 bytes are significant and any additional leading bytes are ignored. It is a requirement of using this cipher that nonce values are unique. Messages encrypted using a reused nonce value are susceptible to serious confidentiality and integrity attacks. If an application changes the default nonce length to be longer than 12 bytes and then makes a change to the leading bytes of the nonce expecting the new value to be a new unique nonce then such an application could inadvertently encrypt messages with a reused nonce. Additionally the ignored bytes in a long nonce are not covered by the integrity guarantee of this cipher. Any application that relies on the integrity of these ignored leading bytes of a long nonce may be further affected. Any OpenSSL internal use of this cipher, including in SSL/TLS, is safe because no such use sets such a long nonce value. However user applications that use this cipher directly and set a non-default nonce length to be longer than 12 bytes may be vulnerable. OpenSSL versions 1.1.1 and 1.1.0 are affected by this issue. Due to the limited scope of affected deployments this has been assessed as low severity and therefore we are not creating new releases at this time. Fixed in OpenSSL 1.1.1c (Affected 1.1.1-1.1.1b). Fixed in OpenSSL 1.1.0k (Affected 1.1.0-1.1.0j).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityW[CVE-2020-1967] openssl: Segmentation fault in SSL_check_chain causes denial of service )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-1967
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2020-1967
Original Description:Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).
Bunknown�	
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability:[CVE-2021-23840] openssl: integer overflow in CipherUpdate )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-23840
Cwe: CWE-190
Reference: https://avd.aquasec.com/nvd/cve-2021-23840
Original Description:Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityQ[CVE-2021-3450] openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT )������@:�CVSS Score: 7.4
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
Cve: CVE-2021-3450
Cwe: CWE-295
Reference: https://avd.aquasec.com/nvd/cve-2021-3450
Original Description:The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow certificates in the chain that have explicitly encoded elliptic curve parameters was added as an additional strict check. An error in the implementation of this check meant that the result of a previous check to confirm that certificates in the chain are valid CA certificates was overwritten. This effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a "purpose" has been configured then there is a subsequent opportunity for checks that the certificate is a valid CA. All of the named "purpose" values implemented in libcrypto perform this check. Therefore, where a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A purpose is set by default in libssl client and server certificate verification routines, but it can be overridden or removed by an application. In order to be affected, an application must explicitly set the X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions 1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).
Bunknown�

>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityC[CVE-2019-1547] openssl: side-channel weak encryption vulnerability )������@:�	CVSS Score: 4.7
CvssVector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
Cve: CVE-2019-1547
Cwe: 
Reference: https://avd.aquasec.com/nvd/cve-2019-1547
Original Description:Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability9[CVE-2019-1549] openssl: information disclosure in fork() )333333@:�CVSS Score: 5.3
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1549
Cwe: CWE-330
Reference: https://avd.aquasec.com/nvd/cve-2019-1549
Original Description:OpenSSL 1.1.1 introduced a rewritten random number generator (RNG). This was intended to include protection in the event of a fork() system call in order to ensure that the parent and child processes did not share the same RNG state. However this protection was not being used in the default case. A partial mitigation for this issue is that the output from a high precision timer is mixed into the RNG state so the likelihood of a parent and child process sharing state is significantly reduced. If an application already calls OPENSSL_init_crypto() explicitly using OPENSSL_INIT_ATFORK then this problem does not occur at all. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityR[CVE-2019-1551] openssl: Integer overflow in RSAZ modular exponentiation on x86_64 )333333@:�CVSS Score: 5.3
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1551
Cwe: CWE-190
Reference: https://avd.aquasec.com/nvd/cve-2019-1551
Original Description:There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability?[CVE-2020-1971] openssl: EDIPARTYNAME NULL pointer de-reference )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-1971
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2020-1971
Original Description:The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityS[CVE-2021-23841] openssl: NULL pointer dereference in X509_issuer_and_serial_hash() )������@:�
CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-23841
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2021-23841
Original Description:The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityT[CVE-2021-3449] openssl: NULL pointer dereference in signature_algorithms processing )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-3449
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2021-3449
Original Description:An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability][CVE-2019-1563] openssl: information disclosure in PKCS7_dataDecode and CMS_decrypt_set1_pkey )������@:�CVSS Score: 3.7
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1563
Cwe: CWE-203,CWE-327
Reference: https://avd.aquasec.com/nvd/cve-2019-1563
Original Description:In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
Bunknown�
>pkg:apk/alpine/libcrypto1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability=[CVE-2021-23839] openssl: incorrect SSLv2 rollback protection )������@:�CVSS Score: 3.7
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
Cve: CVE-2021-23839
Cwe: CWE-327
Reference: https://avd.aquasec.com/nvd/cve-2021-23839
Original Description:OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject connection attempts from a client where this special form of padding is present, because this indicates that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this is the version that is being requested). The implementation of this padding check inverted the logic so that the connection attempt is accepted if the padding is present, and rejected if it is absent. This means that such as server will accept a connection if a version rollback attack has occurred. Further the server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL 1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2 server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding mode. Applications that directly call that function or use that padding mode will encounter this issue. However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability;[CVE-2019-1543] openssl: ChaCha20-Poly1305 with long nonces )������@:�CVSS Score: 7.4
CvssVector: CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
Cve: CVE-2019-1543
Cwe: CWE-327,CWE-330
Reference: https://avd.aquasec.com/nvd/cve-2019-1543
Original Description:ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input for every encryption operation. RFC 7539 specifies that the nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce length and front pads the nonce with 0 bytes if it is less than 12 bytes. However it also incorrectly allows a nonce to be set of up to 16 bytes. In this case only the last 12 bytes are significant and any additional leading bytes are ignored. It is a requirement of using this cipher that nonce values are unique. Messages encrypted using a reused nonce value are susceptible to serious confidentiality and integrity attacks. If an application changes the default nonce length to be longer than 12 bytes and then makes a change to the leading bytes of the nonce expecting the new value to be a new unique nonce then such an application could inadvertently encrypt messages with a reused nonce. Additionally the ignored bytes in a long nonce are not covered by the integrity guarantee of this cipher. Any application that relies on the integrity of these ignored leading bytes of a long nonce may be further affected. Any OpenSSL internal use of this cipher, including in SSL/TLS, is safe because no such use sets such a long nonce value. However user applications that use this cipher directly and set a non-default nonce length to be longer than 12 bytes may be vulnerable. OpenSSL versions 1.1.1 and 1.1.0 are affected by this issue. Due to the limited scope of affected deployments this has been assessed as low severity and therefore we are not creating new releases at this time. Fixed in OpenSSL 1.1.1c (Affected 1.1.1-1.1.1b). Fixed in OpenSSL 1.1.0k (Affected 1.1.0-1.1.0j).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityW[CVE-2020-1967] openssl: Segmentation fault in SSL_check_chain causes denial of service )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-1967
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2020-1967
Original Description:Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).
Bunknown�	
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability:[CVE-2021-23840] openssl: integer overflow in CipherUpdate )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-23840
Cwe: CWE-190
Reference: https://avd.aquasec.com/nvd/cve-2021-23840
Original Description:Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityQ[CVE-2021-3450] openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT )������@:�CVSS Score: 7.4
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
Cve: CVE-2021-3450
Cwe: CWE-295
Reference: https://avd.aquasec.com/nvd/cve-2021-3450
Original Description:The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow certificates in the chain that have explicitly encoded elliptic curve parameters was added as an additional strict check. An error in the implementation of this check meant that the result of a previous check to confirm that certificates in the chain are valid CA certificates was overwritten. This effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a "purpose" has been configured then there is a subsequent opportunity for checks that the certificate is a valid CA. All of the named "purpose" values implemented in libcrypto perform this check. Therefore, where a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A purpose is set by default in libssl client and server certificate verification routines, but it can be overridden or removed by an application. In order to be affected, an application must explicitly set the X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions 1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).
Bunknown�

;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityC[CVE-2019-1547] openssl: side-channel weak encryption vulnerability )������@:�	CVSS Score: 4.7
CvssVector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
Cve: CVE-2019-1547
Cwe: 
Reference: https://avd.aquasec.com/nvd/cve-2019-1547
Original Description:Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability9[CVE-2019-1549] openssl: information disclosure in fork() )333333@:�CVSS Score: 5.3
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1549
Cwe: CWE-330
Reference: https://avd.aquasec.com/nvd/cve-2019-1549
Original Description:OpenSSL 1.1.1 introduced a rewritten random number generator (RNG). This was intended to include protection in the event of a fork() system call in order to ensure that the parent and child processes did not share the same RNG state. However this protection was not being used in the default case. A partial mitigation for this issue is that the output from a high precision timer is mixed into the RNG state so the likelihood of a parent and child process sharing state is significantly reduced. If an application already calls OPENSSL_init_crypto() explicitly using OPENSSL_INIT_ATFORK then this problem does not occur at all. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityR[CVE-2019-1551] openssl: Integer overflow in RSAZ modular exponentiation on x86_64 )333333@:�CVSS Score: 5.3
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1551
Cwe: CWE-190
Reference: https://avd.aquasec.com/nvd/cve-2019-1551
Original Description:There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability?[CVE-2020-1971] openssl: EDIPARTYNAME NULL pointer de-reference )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-1971
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2020-1971
Original Description:The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityS[CVE-2021-23841] openssl: NULL pointer dereference in X509_issuer_and_serial_hash() )������@:�
CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-23841
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2021-23841
Original Description:The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerabilityT[CVE-2021-3449] openssl: NULL pointer dereference in signature_algorithms processing )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2021-3449
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2021-3449
Original Description:An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability][CVE-2019-1563] openssl: information disclosure in PKCS7_dataDecode and CMS_decrypt_set1_pkey )������@:�CVSS Score: 3.7
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Cve: CVE-2019-1563
Cwe: CWE-203,CWE-327
Reference: https://avd.aquasec.com/nvd/cve-2019-1563
Original Description:In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
Bunknown�
;pkg:apk/alpine/libssl1.1@1.1.1a-r1?arch=x86_64&distro=3.9.2Container image vulnerability=[CVE-2021-23839] openssl: incorrect SSLv2 rollback protection )������@:�CVSS Score: 3.7
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
Cve: CVE-2021-23839
Cwe: CWE-327
Reference: https://avd.aquasec.com/nvd/cve-2021-23839
Original Description:OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject connection attempts from a client where this special form of padding is present, because this indicates that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this is the version that is being requested). The implementation of this padding check inverted the logic so that the connection attempt is accepted if the padding is present, and rejected if it is absent. This means that such as server will accept a connection if a version rollback attack has occurred. Further the server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL 1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2 server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding mode. Applications that directly call that function or use that padding mode will encounter this issue. However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x).
Bunknown�
6pkg:apk/alpine/musl@1.1.20-r4?arch=x86_64&distro=3.9.2Container image vulnerability[[CVE-2019-14697] musl libc through 1.1.23 has an x87 floating-point stack adjustment im ... )������#@:�CVSS Score: 9.8
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Cve: CVE-2019-14697
Cwe: CWE-787
Reference: https://avd.aquasec.com/nvd/cve-2019-14697
Original Description:musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application's source code.
Bunknown�
6pkg:apk/alpine/musl@1.1.20-r4?arch=x86_64&distro=3.9.2Container image vulnerability[[CVE-2020-28928] In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... )      @:�CVSS Score: 5.5
CvssVector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-28928
Cwe: CWE-787
Reference: https://avd.aquasec.com/nvd/cve-2020-28928
Original Description:In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).
Bunknown�
<pkg:apk/alpine/musl-utils@1.1.20-r4?arch=x86_64&distro=3.9.2Container image vulnerability[[CVE-2019-14697] musl libc through 1.1.23 has an x87 floating-point stack adjustment im ... )������#@:�CVSS Score: 9.8
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Cve: CVE-2019-14697
Cwe: CWE-787
Reference: https://avd.aquasec.com/nvd/cve-2019-14697
Original Description:musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application's source code.
Bunknown�
<pkg:apk/alpine/musl-utils@1.1.20-r4?arch=x86_64&distro=3.9.2Container image vulnerability[[CVE-2020-28928] In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... )      @:�CVSS Score: 5.5
CvssVector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-28928
Cwe: CWE-787
Reference: https://avd.aquasec.com/nvd/cve-2020-28928
Original Description:In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerabilityF[CVE-2019-8457] sqlite: heap out-of-bound read in function rtreenode() )������#@:�CVSS Score: 9.8
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Cve: CVE-2019-8457
Cwe: CWE-125
Reference: https://avd.aquasec.com/nvd/cve-2019-8457
Original Description:SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable to heap out-of-bound read in the rtreenode() function when handling invalid rtree tables.
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerability�[CVE-2019-19244] sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2019-19244
Cwe: 
Reference: https://avd.aquasec.com/nvd/cve-2019-19244
Original Description:sqlite3Select in select.c in SQLite 3.30.1 allows a crash if a sub-select uses both DISTINCT and window functions, and also has certain ORDER BY usage.
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerabilityZ[CVE-2019-5018] sqlite: Use-after-free in window function leading to remote code execution )333333 @:�CVSS Score: 8.1
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
Cve: CVE-2019-5018
Cwe: CWE-416
Reference: https://avd.aquasec.com/nvd/cve-2019-5018
Original Description:An exploitable use after free vulnerability exists in the window function functionality of Sqlite3 3.26.0. A specially crafted SQL command can cause a use after free vulnerability, potentially resulting in remote code execution. An attacker can send a malicious SQL command to trigger this vulnerability.
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerabilityE[CVE-2020-11655] sqlite: malformed window-function query leads to DoS )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2020-11655
Cwe: CWE-665
Reference: https://avd.aquasec.com/nvd/cve-2020-11655
Original Description:SQLite through 3.31.1 allows attackers to cause a denial of service (segmentation fault) via a malformed window-function query because the AggInfo object's initialization is mishandled.
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerabilityP[CVE-2019-16168] sqlite: Division by zero in whereLoopAddBtreeIndex in sqlite3.c )      @:�CVSS Score: 6.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H
Cve: CVE-2019-16168
Cwe: CWE-369
Reference: https://avd.aquasec.com/nvd/cve-2019-16168
Original Description:In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application because of missing validation of a sqlite_stat1 sz field, aka a "severe division by zero in the query planner."
Bunknown�
=pkg:apk/alpine/sqlite-libs@3.26.0-r3?arch=x86_64&distro=3.9.2Container image vulnerabilityI[CVE-2019-19242] sqlite: SQL injection in sqlite3ExprCodeTarget in expr.c )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2019-19242
Cwe: CWE-476
Reference: https://avd.aquasec.com/nvd/cve-2019-19242
Original Description:SQLite 3.30.1 mishandles pExpr->y.pTab, as demonstrated by the TK_COLUMN case in sqlite3ExprCodeTarget in expr.c.
Bunknown�
pkg:pypi/pip@19.0.3Container image vulnerabilityr[CVE-2019-20916] python-pip: directory traversal in _download_http_url() function in src/pip/_internal/download.py )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
Cve: CVE-2019-20916
Cwe: CWE-22
Reference: https://avd.aquasec.com/nvd/cve-2019-20916
Original Description:The pip package before 19.2 for Python allows Directory Traversal when a URL is given in an install command, because a Content-Disposition header can have ../ in a filename, as demonstrated by overwriting the /root/.ssh/authorized_keys file. This occurs in _download_http_url in _internal/download.py.
Bunknown�
pkg:pypi/pip@19.0.3Container image vulnerabilityV[CVE-2021-3572] python-pip: Incorrect handling of unicode separators in git references )������@:�CVSS Score: 5.7
CvssVector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N
Cve: CVE-2021-3572
Cwe: CWE-20
Reference: https://avd.aquasec.com/nvd/cve-2021-3572
Original Description:A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.
Bunknown�
pkg:pypi/pip@19.0.3Container image vulnerability`[CVE-2023-5752] pip: Mercurial configuration injectable in repo revision when installing via pip )ffffff
@:�CVSS Score: 3.3
CvssVector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N
Cve: CVE-2023-5752
Cwe: CWE-77
Reference: https://avd.aquasec.com/nvd/cve-2023-5752
Original Description:When installing a package from a Mercurial VCS URL  (ie "pip install 
hg+...") with pip prior to v23.3, the specified Mercurial revision could
 be used to inject arbitrary configuration options to the "hg clone" 
call (ie "--config"). Controlling the Mercurial configuration can modify
 how and which repository is installed. This vulnerability does not 
affect users who aren't installing from Mercurial.

Bunknown�
pkg:pypi/setuptools@40.8.0Container image vulnerabilityb[CVE-2022-40897] pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py )������@:�CVSS Score: 5.9
CvssVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2022-40897
Cwe: CWE-1333
Reference: https://avd.aquasec.com/nvd/cve-2022-40897
Original Description:Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of Service (ReDoS) in package_index.py.
Bunknown�
pkg:pypi/wheel@0.33.1Container image vulnerabilityv[CVE-2022-40898] python-wheel: remote attackers can cause denial of service via attacker controlled input to wheel cli )      @:�CVSS Score: 7.5
CvssVector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Cve: CVE-2022-40898
Cwe: 
Reference: https://avd.aquasec.com/nvd/cve-2022-40898
Original Description:An issue discovered in Python Packaging Authority (PyPA) Wheel 0.37.1 and earlier allows remote attackers to cause a denial of service via attacker controlled input to wheel cli.
Bunknown