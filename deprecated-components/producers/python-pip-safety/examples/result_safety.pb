
½§ë³
pip-safetyž
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.26.18]0:½Advisory: Urllib3 1.26.18 and 2.0.7 include a fix for CVE-2023-45803: Request body not stripped after redirect from 303 status changes request method to GET.
https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61893/97cBunknownJCVE-2023-45803É
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.24.2]0:éAdvisory: Affected versions of urllib3 are vulnerable Improper Certificate Validation. Urllib3 mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates, which results in SSL connections succeeding in situations where a verification failure is the correct outcome. This is related to the use of the ssl_context, ca_certs, or ca_certs_dir argument.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37071/97cBunknownJCVE-2019-11324 
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.26.5]0:ÀAdvisory: Urllib3 1.26.5 includes a fix for CVE-2021-33503: When provided with a URL containing many @ characters in the authority component, the authority regular expression exhibits catastrophic backtracking, causing a denial of service if a URL were passed as a parameter or redirected to via an HTTP redirect.
https://github.com/advisories/GHSA-q2q7-5pp4-w6pg
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/43975/97cBunknownJCVE-2021-33503™
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.26.17]0:¸Advisory: Urllib3 1.26.17 and 2.0.5 include a fix for CVE-2023-43804: Urllib3 doesn't treat the 'Cookie' HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a 'Cookie' header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly.
https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61601/97cBunknownJCVE-2023-43804µ
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.25.9]0:ÕAdvisory: Urllib3 1.25.9 includes a fix for CVE-2020-26137: Urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of putrequest(). NOTE: this is similar to CVE-2020-26116.
https://github.com/python/cpython/issues/83784
https://github.com/urllib3/urllib3/pull/1800
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38834/97cBunknownJCVE-2020-26137¾
pkg:pypi/urllib3@1.24.1Vulnerable Dependencyurllib3[<1.24.3]0:ÞAdvisory: Urllib3 1.24.3 includes a fix for CVE-2019-11236: CRLF injection is possible if the attacker controls the request parameter.
https://github.com/urllib3/urllib3/commit/5d523706c7b03f947dc50a7e783758a2bfff0532
https://github.com/urllib3/urllib3/issues/1553
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37055/97cBunknownJCVE-2019-11236™
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<41.0.4]0:±Advisory: Cryptography 41.0.4 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.3, that includes a security fix.
https://github.com/pyca/cryptography/commit/fc11bce6930e591ce26a2317b31b9ce2b3e25512
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62451/97cBunknownJCVE-2023-4807Ã
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<41.0.5]0:ÛAdvisory: Cryptography 41.0.5 updates Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.4, that includes a security fix.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62452/97cBunknownJCVE-2023-5363î
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[>=0.8,<41.0.3]0:€Advisory: Cryptography 41.0.3  updates its bundled OpenSSL version to include a fix for CVE-2023-2975: AES-SIV implementation ignores empty associated data entries.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230714.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60224/97cBunknownJCVE-2023-2975Ã
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/b22271cf3c3dd8dc8978f8f4b00b5c7060b6538d
https://www.openssl.org/news/secadv/20230731.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60223/97cBunknownJCVE-2023-3817Ã
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[>=0.8,<41.0.3]0:ÕAdvisory: Cryptography 41.0.3 updates its bundled OpenSSL version to include a fix for a Denial of Service vulnerability.
https://github.com/pyca/cryptography/commit/bfa4d95f0f356f2d535efd5c775e0fb3efe90ef2
https://www.openssl.org/news/secadv/20230719.txt
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60225/97cBunknownJCVE-2023-3446¤
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<3.3.2]0:¼Advisory: Cryptography 3.3.2 includes a fix for CVE-2020-36242: certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39606/97cBunknownJCVE-2020-36242§
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<3.3]0:ÑAdvisory: Cryptography 3.3 no longer allows loading of finite field Diffie-Hellman parameters of less than 512 bits in length. This change is to conform with an upcoming OpenSSL release that no longer supports smaller sizes. These keys were already wildly insecure and should not have been used in any application outside of testing.
https://github.com/pyca/cryptography/pull/5592
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39252/97cBunknownÑ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53306/97cBunknownJCVE-2023-0217Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53302/97cBunknownJCVE-2023-0216Ô
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:ìAdvisory: Cryptography 39.0.1 includes a fix for CVE-2022-3996, a DoS vulnerability affecting openssl.
https://github.com/pyca/cryptography/issues/7940
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53298/97cBunknownJCVE-2022-3996Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53303/97cBunknownJCVE-2022-4304Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53304/97cBunknownJCVE-2023-0286Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53299/97cBunknownJCVE-2022-4450Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53305/97cBunknownJCVE-2023-0215Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53301/97cBunknownJCVE-2022-4203Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<39.0.1]0:éAdvisory: Cryptography 39.0.1 updates its dependency 'OpenSSL' to v3.0.8 to include security fixes.
https://github.com/pyca/cryptography/issues/8229
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53307/97cBunknownJCVE-2023-0401¦
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<42.0.5]0:ÍAdvisory: Cryptography version 42.0.5 introduces a limit on the number of name constraint checks during X.509 path validation to prevent denial of service attacks.
https://github.com/pyca/cryptography/commit/4be53bf20cc90cbac01f5f94c5d1aecc5289ba1f
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65647/97cBunknown¼
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<42.0.0]0:ÓAdvisory: A flaw was found in the python-cryptography package. This issue may allow a remote attacker to decrypt captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or sensitive data. See CVE-2023-50782.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65278/97cBunknownJCVE-2023-50782‹
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<42.0.0]0:£Advisory: Cryptography starting from version 42.0.0 updates its CI configurations to use newer versions of BoringSSL or OpenSSL as a countermeasure to CVE-2023-5678. This vulnerability, affecting the package, could cause Denial of Service through specific DH key generation and verification functions when given overly long parameters.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65510/97cBunknownJCVE-2023-5678°
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<41.0.2]0:ÇAdvisory: The cryptography package before 41.0.2 for Python mishandles SSH certificates that have critical options.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59473/97cBunknownJCVE-2023-38325à
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<=3.2]0:ùAdvisory: Cryptography 3.2 and prior are vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38932/97cBunknownJCVE-2020-25659Ñ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[>=1.8,<39.0.1]0:âAdvisory: Cryptography 39.0.1 includes a fix for CVE-2023-23931: In affected versions 'Cipher.update_into' would accept Python objects which implement the buffer protocol, but provide only immutable buffers. This would allow immutable objects (such as 'bytes') to be mutated, thus violating fundamental rules of Python and resulting in corrupted output. This issue has been present since 'update_into' was originally introduced in cryptography 1.8.
https://github.com/pyca/cryptography/security/advisories/GHSA-w7pp-m8wf-vj6r
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53048/97cBunknownJCVE-2023-23931õ
pkg:pypi/cryptography@2.6.1Vulnerable Dependencycryptography[<41.0.0]0:Advisory: Cryptography 41.0.0 updates its dependency 'OpenSSL' to v3.1.1 to include a security fix.
https://github.com/pyca/cryptography/commit/8708245ccdeaff21d65eea68a4f8d2a7c5949a22
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59062/97cBunknownJCVE-2023-2650Œ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<7.1.0]0:°Advisory: In Pillow before 7.1.0, there are two Buffer Overflows in libImaging/TiffDecode.c.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38450/97cBunknownJCVE-2020-10379‰
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<7.1.0]0:­Advisory: Pillow before 7.1.0 has multiple out-of-bounds reads in libImaging/FliDecode.c.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38448/97cBunknownJCVE-2020-10177ã
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<7.1.0]0:‡Advisory: In libImaging/PcxDecode.c in Pillow before 7.1.0, an out-of-bounds read can occur when reading PCX files where state->shuffle is instructed to read beyond state->buffer.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38449/97cBunknownJCVE-2020-10378­
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<7.1.0]0:ÑAdvisory: In libImaging/Jpeg2KDecode.c in Pillow before 7.1.0, there are multiple out-of-bounds reads via a crafted JP2 file.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38451/97cBunknownJCVE-2020-10994Ð
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[>=0,<8.1.2]0:€Advisory: Certain versions of Pillow are susceptible to a denial of service via memory consumption due to inadequate validation of the reported size of a contained image in a BLP container. This can result in attempts to allocate excessively large amounts of memory. To mitigate or avoid this vulnerability, users should consider updating to a newer version that addresses the issue or following any provided workarounds, such as avoiding the processing of specially crafted invalid image files that may trigger this condition. For additional details and potential updates, users may refer to the CVE-2021-27921 entry or contact the software maintainers through the provided channels.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/69615/97cBunknown
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<10.2.0]0:ÃAdvisory: Pillow is potentially vulnerable to DoS attacks through PIL.ImageFont.ImageFont.getmask(). A decompression bomb check has also been added to the affected function.
https://pillow.readthedocs.io/en/stable/releasenotes/10.2.0.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/64437/97cBunknownÎ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<10.2.0]0:ñAdvisory: Pillow is affected by an arbitrary code execution vulnerability. If an attacker has control over the keys passed to the environment argument of PIL.ImageMath.eval(), they may be able to execute arbitrary code.
https://pillow.readthedocs.io/en/stable/releasenotes/10.2.0.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/64436/97cBunknownJCVE-2023-50447‡
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.2.0]0:«Advisory: Pillow version 8.2.0 includes a fix for CVE-2021-28676: For FLI data, FliDecode did not properly check that the block advance was non-zero, potentially leading to an infinite loop on load.
https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQHA5HAIBOYI3R6HDWCLAGFTIQP767FL/
https://github.com/python-pillow/Pillow/pull/5377
https://pillow.readthedocs.io/en/stable/releasenotes/8.2.0.html#cve-2021-28676-fix-fli-dos
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40594/97cBunknownJCVE-2021-28676Ï
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.2.0]0:óAdvisory: Pillow version 8.2.0 includes a fix for CVE-2021-28678: For BLP data, BlpImagePlugin did not properly check that reads (after jumping to file offsets) returned data. This could lead to a DoS where the decoder could be run a large number of times on empty data.
https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQHA5HAIBOYI3R6HDWCLAGFTIQP767FL/
https://github.com/python-pillow/Pillow/pull/5377
https://pillow.readthedocs.io/en/stable/releasenotes/8.2.0.html#cve-2021-28678-fix-blp-dos
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40596/97cBunknownJCVE-2021-28678¢
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.2.0]0:ÆAdvisory: Pillow 8.2.0 includes a fix for CVE-2021-25288: There is an out-of-bounds read in J2kDecode, in j2ku_gray_i.
https://pillow.readthedocs.io/en/stable/releasenotes/8.2.0.html#cve-2021-25287-cve-2021-25288-fix-oob-read-in-jpeg2kdecode
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40593/97cBunknownJCVE-2021-25288¤
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.2.0]0:ÈAdvisory: Pillow 8.2.0 includes a fix for CVE-2021-25287: There is an out-of-bounds read in J2kDecode, in j2ku_graya_la.
https://pillow.readthedocs.io/en/stable/releasenotes/8.2.0.html#cve-2021-25287-cve-2021-25288-fix-oob-read-in-jpeg2kdecode
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40592/97cBunknownJCVE-2021-25287ä
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.2.0]0:ˆAdvisory: Pillow version 8.2.0 includes a fix for CVE-2021-28677: For EPS data, the readline implementation used in EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.
https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQHA5HAIBOYI3R6HDWCLAGFTIQP767FL/
https://github.com/python-pillow/Pillow/pull/5377
https://pillow.readthedocs.io/en/stable/releasenotes/8.2.0.html#cve-2021-28677-fix-eps-dos-on-open
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40595/97cBunknownJCVE-2021-28677×
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.1.1]0:ûAdvisory: Pillow 9.1.1 addresses the CVE-2022-30595: libImaging/TgaRleDecode.c in Pillow 9.1.0 has a heap buffer overflow in the processing of invalid TGA image files.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/67137/97cBunknownJCVE-2022-30595Õ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[>=5.2.0,<8.3.2]0:ñAdvisory: Pillow from 5.2.0 and before 8.3.2 is vulnerable to Regular Expression Denial of Service (ReDoS) via the getrgb function.
https://github.com/python-pillow/Pillow/commit/9e08eb8f78fdfd2f476e1b20b7cf38683754866b
https://pillow.readthedocs.io/en/stable/releasenotes/8.3.2.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/41271/97cBunknownJCVE-2021-23437È
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.3.0]0:ìAdvisory: Pillow 8.3.0 includes a fix for CVE-2021-34552: Pillow through 8.2.0 and PIL (also known as Python Imaging Library) through 1.1.7 allow an attacker to pass controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c
https://pillow.readthedocs.io/en/stable/releasenotes/8.3.0.html#buffer-overflow
https://pillow.readthedocs.io/en/stable/releasenotes/index.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40965/97cBunknownJCVE-2021-34552¡
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[>=0,<8.2.0]0:ÁAdvisory: An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile lacked a sanity check on the number of input layers relative to the size of the data block. This could lead to a DoS on Image.open prior to Image.load.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/54688/97cBunknownJCVE-2021-28675ý
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.0]0:±Advisory: Pillow 9.0.0 ensures JpegImagePlugin stops at the end of a truncated file to avoid Denial of Service attacks.
https://github.com/python-pillow/Pillow/pull/5921
https://github.com/advisories/GHSA-4fx9-vc88-q2xc
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44524/97cBunknownÿ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.0]0:³Advisory: Pillow 9.0.0 excludes carriage return in PDF regex to help prevent ReDoS.
https://github.com/python-pillow/Pillow/pull/5912
https://github.com/python-pillow/Pillow/commit/43b800d933c996226e4d7df00c33fcbe46d97363
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44525/97cBunknown¼
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.0]0:àAdvisory: Pillow 9.0.0 includes a fix for CVE-2022-22816: path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of ImagePath.Path.
https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44486/97cBunknownJCVE-2022-22816£
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.0]0:ÇAdvisory: Pillow 9.0.0 includes a fix for CVE-2022-22815: path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path.
https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44485/97cBunknownJCVE-2022-22815ˆ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:¬Advisory: Pillow 8.1.1 includes a fix for CVE-2021-25289: TiffDecode has a heap-based buffer overflow when decoding crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode. NOTE: this issue exists because of an incomplete fix for CVE-2020-35654.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40274/97cBunknownJCVE-2021-25289‹
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:¯Advisory: Pillow 8.1.1 includes a fix for CVE-2021-25291: In TiffDecode.c, there is an out-of-bounds read in TiffreadRGBATile via invalid tile boundaries.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40272/97cBunknownJCVE-2021-25291Ü
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:€Advisory: Pillow 8.1.1 includes a fix for CVE-2021-25293: There is an out-of-bounds read in SGIRleDecode.c.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40273/97cBunknownJCVE-2021-25293ó
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:—Advisory: Pillow 8.1.1 includes a fix for CVE-2021-25290: In TiffDecode.c, there is a negative-offset memcpy with an invalid size.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40275/97cBunknownJCVE-2021-25290˜
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:¼Advisory: Pillow 8.1.1 includes a fix for CVE-2021-27921: Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for a BLP container, and thus an attempted memory allocation can be very large.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40263/97cBunknownJCVE-2021-27921­
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:ÑAdvisory: Pillow 8.1.1 includes a fix for CVE-2021-25292: The PDF parser allows a regular expression DoS (ReDoS) attack via a crafted PDF file because of a catastrophic backtracking regex.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40266/97cBunknownJCVE-2021-25292š
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.1]0:¾Advisory: Pillow 8.1.1 includes a fix for CVE-2021-27922: Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICNS container, and thus an attempted memory allocation can be very large.
https://pillow.readthedocs.io/en/stable/releasenotes/8.1.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40267/97cBunknownJCVE-2021-27922•
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.0.1]0:¹Advisory: Pillow 8.0.1 updates 'FreeType' used in binary wheels to v2.10.4 to include a security fix.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40264/97cBunknownJCVE-2020-15999œ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.2.0]0:ÀAdvisory: Pillow before 9.2.0 performs Improper Handling of Highly Compressed GIF Data (Data Amplification).
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/51885/97cBunknownJCVE-2022-45198Š
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.0]0:®Advisory: Pillow 8.1.0 includes a fix for SGI Decode buffer overrun. CVE-2020-35655 #5173.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40271/97cBunknownJCVE-2020-35655ø
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.0]0:œAdvisory: Pillow 8.1.0 fixes TIFF OOB Write error. CVE-2020-35654 #5175.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40265/97cBunknownJCVE-2020-35654Þ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<8.1.0]0:‚Advisory: In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the user-supplied stride value is trusted for buffer calculations.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40270/97cBunknownJCVE-2020-35653°
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[>=4.3.0,<8.1.1]0:ÌAdvisory: Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICO container, and thus an attempted memory allocation can be very large.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40268/97cBunknownJCVE-2021-27923·
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.2]0:ÛAdvisory: There is a DoS vulnerability in Pillow before 6.2.2 caused by FpxImagePlugin.py calling the range function on an unvalidated 32-bit integer if the number of bands is large. On Windows running 32-bit Python, this results in an OverflowError or MemoryError due to the 2 GB limit. However, on Linux running 64-bit Python this results in the process being terminated by the OOM killer.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37772/97cBunknownJCVE-2019-19911…
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.2]0:ªAdvisory: libImaging/SgiRleDecode.c in Pillow before 6.2.2 has an SGI buffer overflow.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37780/97cBunknownJCVE-2020-5311¡
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.2]0:ÆAdvisory: libImaging/TiffDecode.c in Pillow before 6.2.2 has a TIFF decoding integer overflow, related to realloc.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37779/97cBunknownJCVE-2020-5310ˆ
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.2]0:­Advisory: libImaging/PcxDecode.c in Pillow before 6.2.2 has a PCX P mode buffer overflow.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37781/97cBunknownJCVE-2020-5312‚
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.2]0:§Advisory: libImaging/FliDecode.c in Pillow before 6.2.2 has an FLI buffer overflow.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/37782/97cBunknownJCVE-2020-5313ß
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<=7.0.0]0:‚Advisory: In libImaging/SgiRleDecode.c in Pillow through 7.0.0, a number of out-of-bounds reads exist in the parsing of SGI image files, a different issue than CVE-2020-5311.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38452/97cBunknownJCVE-2020-11538¦
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<10.0.0]0:ÉAdvisory: Pillow 10.0.0 includes a fix for CVE-2023-44271: Denial of Service that uncontrollably allocates memory to process a given task, potentially causing a service to crash by having it run out of memory. This occurs for truetype in ImageFont when textlength in an ImageDraw instance operates on a long text argument.
https://github.com/python-pillow/Pillow/pull/7244
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62156/97cBunknownJCVE-2023-44271Î
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<10.3.0]0:ñAdvisory: Pillow 10.3.0 introduces a security update addressing CVE-2024-28219 by replacing certain functions with strncpy to prevent buffer overflow issues.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/67136/97cBunknownJCVE-2024-28219É
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<6.2.0]0:íAdvisory: Pillow 6.2.0 includes a fix for CVE-2019-16865: An issue was discovered in Pillow before 6.2.0. When reading specially crafted invalid image files, the library can either allocate very large amounts of memory or take an extremely long period of time to process the image.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44744/97cBunknownJCVE-2019-16865¤
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.1]0:ÈAdvisory: Pillow before 9.0.1 allows attackers to delete files because spaces in temporary pathnames are mishandled.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/45356/97cBunknownJCVE-2022-24303£
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[<9.0.1]0:ÇAdvisory: Pillow 9.0.1 includes a fix for CVE-2022-22817: PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method. A first patch was issued for version 9.0.0 but it did not prevent builtins available to lambda expressions.
https://pillow.readthedocs.io/en/stable/releasenotes/9.0.1.html#security
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44487/97cBunknownJCVE-2022-22817í
pkg:pypi/pillow@5.4.1Vulnerable Dependencypillow[>=2.5.0,<10.0.1]0:‰Advisory: Pillow 10.0.1 updates its C dependency 'libwebp' to 1.3.2 to include a fix for a high-risk vulnerability.
https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61489/97cBunknownJCVE-2023-4863è
pkg:pypi/lxml@4.2.5Vulnerable Dependencylxml[<4.4.0]0: Advisory: In lxml before 4.4.0, when writing to file paths that contain the URL escape character '%', the file path could wrongly be mangled by URL unescaping and thus write to a different file or directory.  Code that writes to file paths that are provided by untrusted sources, but that must work with previous versions of lxml, should best either reject paths that contain '%' characters, or otherwise make sure that the path does not contain maliciously injected '%XX' URL hex escapes for paths like '../'.
https://github.com/lxml/lxml/commit/0245aba002f069a0b157282707bdf77418d1b5be
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39195/97cBunknownð
pkg:pypi/lxml@4.2.5Vulnerable Dependencylxml[<4.6.2]0:˜Advisory: Lxml 4.6.2 includes a fix for CVE-2020-27783: A XSS vulnerability was discovered in python-lxml's clean module. The module's parser didn't properly imitate browsers, which caused different behaviors between the sanitizer and the user's page. A remote attacker could exploit this flaw to run arbitrary HTML/JS code.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39194/97cBunknownJCVE-2020-27783ÿ
pkg:pypi/lxml@4.2.5Vulnerable Dependencylxml[<4.6.5]0:§Advisory: Lxml 4.6.5 includes a fix for CVE-2021-43818: Prior to version 4.6.5, the HTML Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should upgrade to lxml 4.6.5 to receive a patch.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/43366/97cBunknownJCVE-2021-43818‡
pkg:pypi/lxml@4.2.5Vulnerable Dependencylxml[<4.6.3]0:¯Advisory: Lxml version 4.6.3 includes a fix for CVE-2021-28957: An XSS vulnerability was discovered in python-lxml's clean module versions before 4.6.3. When disabling the safe_attrs_only and forms arguments, the Cleaner class does not remove the formation attribute allowing for JS to bypass the sanitizer. A remote attacker could exploit this flaw to run arbitrary JS code on users who interact with incorrectly sanitized HTML.
https://bugs.launchpad.net/lxml/+bug/1888153
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40072/97cBunknownJCVE-2021-28957š
pkg:pypi/lxml@4.2.5Vulnerable Dependencylxml[<4.9.1]0:ÃAdvisory: Lxml 4.9.1 includes a fix for CVE-2022-2309: NULL Pointer Dereference allows attackers to cause a denial of service (or application crash). This only applies when lxml is used together with libxml2 2.9.10 through 2.9.14. libxml2 2.9.9 and earlier are not affected. It allows triggering crashes through forged input data, given a vulnerable code sequence in the application. The vulnerability is caused by the iterwalk function (also used by the canonicalize function). Such code shouldn't be in wide-spread use, given that parsing + iterwalk would usually be replaced with the more efficient iterparse function. However, an XML converter that serialises to C14N would also be vulnerable, for example, and there are legitimate use cases for this code sequence. If untrusted input is received (also remotely) and processed via iterwalk function, a crash can be triggered.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50748/97cBunknownJCVE-2022-2309°
pkg:pypi/scikit-learn@0.20.2Vulnerable Dependencyscikit-learn[<0.24.2]0:ÖAdvisory: Scikit-learn 0.24.2 includes a fix for a ReDoS vulnerability.
https://github.com/scikit-learn/scikit-learn/issues/19522
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52255/97cBunknownÍ
pkg:pypi/scikit-learn@0.20.2Vulnerable Dependencyscikit-learn[<1.1.0rc1]0:áAdvisory: Scikit-learn 1.1.0rc1 includes a fix for CVE-2020-28975: svm_predict_values in svm.cpp in Libsvm v324, as used in scikit-learn and other products, allows attackers to cause a denial of service (segmentation fault) via a crafted model SVM (introduced via pickle, json, or any other model permanence standard) with a large value in the _n_support array. 
NOTE: the scikit-learn vendor's position is that the behavior can only occur if the library's API is violated by an application that changes a private attribute.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/54297/97cBunknownJCVE-2020-28975®
pkg:pypi/scipy@1.2.0Vulnerable Dependencyscipy[<1.10.0rc1]0:ÐAdvisory: Scipy 1.10.0rc1 includes a fix for a Denial of Service vulnerability.
https://github.com/scipy/scipy/issues/16235
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59399/97cBunknownJCVE-2023-25399¤
pkg:pypi/scipy@1.2.0Vulnerable Dependencyscipy[<1.8.0]0:ÊAdvisory: Scipy 1.8.0 includes a fix for an Use After Free vulnerability.
https://github.com/scipy/scipy/issues/14713
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59398/97cBunknownJCVE-2023-29824ú

pkg:pypi/flask@1.0.2Vulnerable Dependencyflask[<2.2.5]0: 
Advisory: Flask 2.2.5 and 2.3.2 include a fix for CVE-2023-30861: When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches 'Set-Cookie' headers, it may send one client's 'session' cookie to other clients. The severity depends on the application's use of the session and the proxy's behavior regarding cookies. The risk depends on all these conditions being met:
1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets 'session.permanent = True'
3. The application does not access or modify the session at any point during a request.
4. 'SESSION_REFRESH_EACH_REQUEST' enabled (the default).
5. The application does not set a 'Cache-Control' header to indicate that a page is private or should not be cached.
This happens because vulnerable versions of Flask only set the 'Vary: Cookie' header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified.
https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/55261/97cBunknownJCVE-2023-30861­
pkg:pypi/numpy@1.16.0Vulnerable Dependencynumpy[<1.16.3]0:ÒAdvisory: Numpy 1.16.3 includes a fix for CVE-2019-6446: It uses the pickle Python module unsafely, which allows remote attackers to execute arbitrary code via a crafted serialized object, as demonstrated by a numpy.load call.
NOTE: Third parties dispute this issue because it is  a behavior that might have legitimate applications in (for example) loading serialized Python object arrays from trusted and authenticated  sources.
https://github.com/numpy/numpy/commit/89b688732b37616c9d26623f81aaee1703c30ffb
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/36810/97cBunknownJCVE-2019-6446«
pkg:pypi/numpy@1.16.0Vulnerable Dependencynumpy[<1.22.2]0:ÏAdvisory: Numpy 1.22.2  includes a fix for CVE-2021-41495: Null Pointer Dereference vulnerability exists in numpy.sort in NumPy in the PyArray_DescrNew function due to missing return-value validation, which allows attackers to conduct DoS attacks by repetitively creating sort arrays. 
NOTE: While correct that validation is missing, an error can only occur due to an exhaustion of memory. If the user can exhaust memory, they are already privileged. Further, it should be practically impossible to construct an attack which can target the memory exhaustion to occur at exactly this place.
https://github.com/numpy/numpy/issues/19038
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44715/97cBunknownJCVE-2021-41495ž
pkg:pypi/numpy@1.16.0Vulnerable Dependencynumpy[<1.22.0]0:ÂAdvisory: Numpy 1.22.0 includes a fix for CVE-2021-34141: An incomplete string comparison in the numpy.core component in NumPy before 1.22.0 allows attackers to trigger slightly incorrect copying by constructing specific string objects. 
NOTE: the vendor states that this reported code behavior is "completely harmless."
https://github.com/numpy/numpy/issues/18993
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44717/97cBunknownJCVE-2021-34141è
pkg:pypi/numpy@1.16.0Vulnerable Dependencynumpy[<1.22.0]0:ŒAdvisory: Numpy 1.22.0 includes a fix for CVE-2021-41496: Buffer overflow in the array_from_pyobj function of fortranobject.c, which allows attackers to conduct a Denial of Service attacks by carefully constructing an array with negative values. 
NOTE: The vendor does not agree this is a vulnerability; the negative dimensions can only be created by an already privileged user (or internally).
https://github.com/numpy/numpy/issues/19000
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44716/97cBunknownJCVE-2021-41496ÿ
pkg:pypi/numpy@1.16.0Vulnerable Dependencynumpy[<1.21.0rc1]0: Advisory: Numpy 1.21.0rc1 includes a fix for CVE-2021-33430: A Buffer Overflow vulnerability in the PyArray_NewFromDescr_int function of ctors.c when specifying arrays of large dimensions (over 32) from Python code, which could let a malicious user cause a Denial of Service. 
NOTE: The vendor does not agree this is a vulnerability. In (very limited) circumstances a user may be able provoke the buffer overflow, the user is most likely already privileged to at least provoke denial of service by exhausting memory. Triggering this further requires the use of uncommon API (complicated structured dtypes), which is very unlikely to be available to an unprivileged user.
https://github.com/numpy/numpy/issues/18939
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/43453/97cBunknownJCVE-2021-33430Ý
pkg:pypi/requests@2.20.0Vulnerable Dependencyrequests[>=2.3.0,<2.31.0]0:óAdvisory: Requests 2.31.0 includes a fix for CVE-2023-32681: Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use 'rebuild_proxies' to reattach the 'Proxy-Authorization' header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the 'Proxy-Authorization' header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/58755/97cBunknownJCVE-2023-32681‘
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.16]0:²Advisory: In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized URLs were subject to a potential denial of service attack via the locale parameter, which is treated as a regular expression.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/51340/97cBunknownJCVE-2022-41323î
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.17]0:Advisory: Django 3.2.17, 4.0.9 and 4.1.6 includes a fix for CVE-2023-23969: In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language headers are cached in order to avoid repetitive parsing. This leads to a potential denial-of-service vector via excessive memory usage if the raw value of Accept-Language headers is very large.
https://www.djangoproject.com/weblog/2023/feb/01/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/52945/97cBunknownJCVE-2023-23969ë
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.26]0:ŒAdvisory: Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45115: UserAttributeSimilarityValidator incurred significant overhead in evaluating a submitted password that was artificially large in relation to the comparison values. In a situation where access to user registration was unrestricted, this provided a potential vector for a denial-of-service attack.
https://www.djangoproject.com/weblog/2022/jan/04/security-releases/
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44423/97cBunknownJCVE-2021-45115ÿ
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.26]0: Advisory: Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45116: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to leveraging the Django Template Language's variable resolution logic, the dictsort template filter was potentially vulnerable to information disclosure, or an unintended method call, if passed a suitably crafted key.
https://www.djangoproject.com/weblog/2022/jan/04/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44427/97cBunknownJCVE-2021-45116à
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.26]0:Advisory: Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45452: Storage.save in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1 allows directory traversal if crafted filenames are directly passed to it.
https://www.djangoproject.com/weblog/2022/jan/04/security-releases/
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44426/97cBunknownJCVE-2021-45452¿
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.21]0:àAdvisory: Django 2.2.21, 3.1.9 and 3.2.1 include a fix for CVE-2021-31542: MultiPartParser, UploadedFile, and FieldFile allowed directory traversal via uploaded files with suitably crafted file names.
https://www.djangoproject.com/weblog/2021/may/04/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40404/97cBunknownJCVE-2021-31542†
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.14]0:§Advisory: Django 3.2.14 and 4.0.6 include a fix for CVE-2022-34265: Potential SQL injection via Trunc(kind) and Extract(lookup_name) arguments.
https://www.djangoproject.com/weblog/2022/jul/04/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/49733/97cBunknownJCVE-2022-34265£
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.24]0:ÄAdvisory: Django 2.2.24, 3.1.12, and 3.2.4 include a fix for CVE-2021-33571: In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit leading zero characters in octal literals. This may allow a bypass of access control that is based on IP addresses. (validate_ipv4_address and validate_ipv46_address are unaffected with Python 3.9.5+).
https://www.djangoproject.com/weblog/2021/jun/02/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40638/97cBunknownJCVE-2021-33571’
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.24]0:³Advisory: Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a potential directory traversal via django.contrib.admindocs. Staff members could use the TemplateDetailView view to check the existence of arbitrary files. Additionally, if (and only if) the default admindocs templates have been customized by application developers to also show file contents, then not only the existence but also the file contents would have been exposed. In other words, there is directory traversal outside of the template root directories.
https://www.djangoproject.com/weblog/2021/jun/02/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/40637/97cBunknownJCVE-2021-33203¹
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.19]0:ÚAdvisory: Django versions 2.2.19, 3.0.13 and 3.1.7 include a fix for CVE-2021-23336: Web cache poisoning via 'django.utils.http.limited_parse_qsl()'. Django contains a copy of 'urllib.parse.parse_qsl' which was added to backport some security fixes. A further security fix has been issued recently such that 'parse_qsl(' no longer allows using ';' as a query parameter separator by default.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39646/97cBunknownJCVE-2021-23336±
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.19]0:ÒAdvisory: Django 4.2.1, 4.1.9 and 3.2.19 include a fix for CVE-2023-31047: In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files. This multiple upload has never been supported by forms.FileField or forms.ImageField (only the last uploaded file was validated). However, Django's "Uploading multiple files" documentation suggested otherwise.
https://www.djangoproject.com/weblog/2023/may/03/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/55264/97cBunknownJCVE-2023-31047â
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.27]0:ƒAdvisory: The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not properly encode the current context. This may lead to XSS.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44742/97cBunknownJCVE-2022-22818ñ
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.27]0:’Advisory: Django 2.2.27, 3.2.12 and 4.0.2 include a fix for CVE-2022-23833: Denial-of-service possibility in file uploads.
https://www.djangoproject.com/weblog/2022/feb/01/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/44741/97cBunknownJCVE-2022-23833ï
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.21]0:Advisory: Affected versions of Django are vulnerable to potential Denial of Service via certain inputs with a very large number of Unicode characters in django.utils.encoding.uri_to_iri().
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/60956/97cBunknownJCVE-2023-41164‡
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.16]0:¨Advisory: Django 2.2.16, 3.0.10 and 3.1.1 include a fix for CVE-2020-24583: An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before 3.1.1 (when Python 3.7+ is used). FILE_UPLOAD_DIRECTORY_PERMISSIONS mode was not applied to intermediate-level directories created in the process of uploading files. It was also not applied to intermediate-level collected static directories when using the collectstatic management command.
#NOTE: This vulnerability affects only users of Python versions above 3.7.
https://www.djangoproject.com/weblog/2020/sep/01/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38749/97cBunknownJCVE-2020-24583£
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.16]0:ÄAdvisory: An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before 3.1.1 (when Python 3.7+ is used). The intermediate-level directories of the filesystem cache had the system's standard umask rather than 0o077.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/38752/97cBunknownJCVE-2020-24584²
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.1.9]0:ÔAdvisory: Django versions 2.1.9 and 2.2.2 include a patched bundled jQuery version to avoid a Prototype Pollution vulnerability.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/39594/97cBunknownJCVE-2019-11358‰
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.23]0:ªAdvisory: Django 4.2.7, 4.1.13 and 3.2.23 include a fix for CVE-2023-46695: Potential denial of service vulnerability in UsernameField on Windows.
https://www.djangoproject.com/weblog/2023/nov/01/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/62126/97cBunknownJCVE-2023-46695Ü
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.15]0:ýAdvisory: Django 3.2.15 and 4.0.7 include a fix for CVE-2022-36359: An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7. An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition header of a FileResponse when the filename is derived from user-supplied input.
https://www.djangoproject.com/weblog/2022/aug/03/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/50454/97cBunknownJCVE-2022-36359Ÿ
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.25]0:ÀAdvisory: Affected versions of Django are vulnerable to potential regular expression denial-of-service (REDoS). django.utils.text.Truncator.words() method (with html=True) and truncatewords_html template filter were subject to a potential regular expression denial-of-service attack using a suitably crafted string (follow up to CVE-2019-14232 and CVE-2023-43665).
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/65771/97cBunknownJCVE-2024-27351Ä
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.24]0:åAdvisory: Affected versions of Django are vulnerable to potential denial-of-service in intcomma template filter when used with very long strings.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/64976/97cBunknownJCVE-2024-24680ý
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.18]0:žAdvisory: Django 4.1.7, 4.0.10 and 3.2.18 include a fix for CVE-2023-24580: Potential denial-of-service vulnerability in file uploads.
https://www.djangoproject.com/weblog/2023/feb/14/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/53315/97cBunknownJCVE-2023-24580Û
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.28]0:üAdvisory: Django 2.2.28, 3.2.13 and 4.0.4 include a fix for CVE-2022-28347: A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. This occurs by passing a crafted dictionary (with dictionary expansion) as the **options argument, and placing the injection payload in an option name.
https://www.djangoproject.com/weblog/2022/apr/11/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/48040/97cBunknownJCVE-2022-28347Ò
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.28]0:óAdvisory: Django 2.2.28, 3.2.13 and 4.0.4 include a fix for CVE-2022-28346: An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.
https://www.djangoproject.com/weblog/2022/apr/11/security-releases
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/48041/97cBunknownJCVE-2022-28346û
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<2.2.25]0:œAdvisory: Django versions 2.2.25, 3.1.14 and 3.2.10 include a fix for CVE-2021-44420: In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths.
https://www.djangoproject.com/weblog/2021/dec/07/security-releases/
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/43041/97cBunknownJCVE-2021-44420ˆ
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.20]0:©Advisory: Affected versions of Django are vulnerable to a potential ReDoS (regular expression denial of service) in EmailValidator and URLValidator via a very large number of domain name labels of emails and URLs.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/59293/97cBunknownJCVE-2023-36053Ñ
pkg:pypi/django@1.11.29Vulnerable Dependencydjango[<3.2.22]0:òAdvisory: Affected versions of Django are vulnerable to Denial-of-Service via django.utils.text.Truncator. The django.utils.text.Truncator chars() and words() methods (when used with html=True) are subject to a potential DoS (denial of service) attack via certain inputs with very long, potentially malformed HTML text. The chars() and words() methods are used to implement the truncatechars_html and truncatewords_html template filters, which are thus also vulnerable. NOTE: this issue exists because of an incomplete fix for CVE-2019-14232.
Fixed Versions: [],Resources: [], More Info: https://data.safetycli.com/v/61586/97cBunknownJCVE-2023-43665