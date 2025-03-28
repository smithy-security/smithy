
ÕŽ°´
yarn-auditØ
pkg:npm/mquery@3.2.01086439Code Injection in mquery 0:üVulnerable Versions: <3.2.3
Recommendation: Upgrade to version 3.2.3 or later
Overview: lib/utils.js in mquery before 3.2.3 allows a pollution attack because a special property (e.g., __proto__) can be copied during a merge or clone operation.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2020-35149
- https://github.com/aheckmann/mquery/commit/792e69fd0a7281a0300be5cade5a6d7c1d468ad4
- https://github.com/advisories/GHSA-45q2-34rf-mr94
Advisory URL: https://github.com/advisories/GHSA-45q2-34rf-mr94
BunknownJCVE-2020-35149j^Ý
pkg:npm/mongodb@3.1.101086754Denial of Service in mongodb 0:ŽVulnerable Versions: <3.1.13
Recommendation: Upgrade to version 3.1.13 or later
Overview: Versions of `mongodb` prior to 3.1.13 are vulnerable to Denial of Service. The package fails to properly catch an exception when a collection name is invalid and the DB does not exist, crashing the application.


## Recommendation

Upgrade to version 3.1.13 or later.
References:
- https://www.npmjs.com/advisories/1203
- https://github.com/advisories/GHSA-mh5c-679w-hh4r
Advisory URL: https://github.com/advisories/GHSA-mh5c-679w-hh4r
Bunknownª
pkg:npm/mpath@0.5.11095075Type confusion in mpath 0:ÏVulnerable Versions: <0.8.4
Recommendation: Upgrade to version 0.8.4 or later
Overview: This affects the package mpath before 0.8.4. A type confusion vulnerability can lead to a bypass of CVE-2018-16490. In particular, the condition `ignoreProperties.indexOf(parts[i]) !== -1` returns `-1` if `parts[i]` is `['__proto__']`. This is because the method that has been called if the input is an array is `Array.prototype.indexOf()` and not `String.prototype.indexOf()`. They behave differently depending on the type of the input.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2021-23438
- https://github.com/aheckmann/mpath/commit/89402d2880d4ea3518480a8c9847c541f2d824fc
- https://snyk.io/vuln/SNYK-JS-MPATH-1577289
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1579548
- https://github.com/mongoosejs/mpath/commit/89402d2880d4ea3518480a8c9847c541f2d824fc
- https://github.com/advisories/GHSA-p92x-r36w-9395
Advisory URL: https://github.com/advisories/GHSA-p92x-r36w-9395
BunknownJCVE-2021-23438jËˆ	
pkg:npm/mongoose@5.4.010950770Improper Input Validation in Automattic Mongoose 0:’Vulnerable Versions: >=5.0.0 <5.7.5
Recommendation: Upgrade to version 5.7.5 or later
Overview: Automattic Mongoose through 5.7.4 allows attackers to bypass access control (in some applications) because any query object with a `_bsontype` attribute is ignored. For example, adding `"_bsontype":"a"` can sometimes interfere with a query filter. NOTE: this CVE is about Mongoose's failure to work around this _bsontype special case that exists in older versions of the bson parser (aka the mongodb/js-bson project).
References:
- https://nvd.nist.gov/vuln/detail/CVE-2019-17426
- https://github.com/Automattic/mongoose/commit/f3eca5b94d822225c04e96cbeed9f095afb3c31c
- https://github.com/Automattic/mongoose/issues/8222
- https://github.com/Automattic/mongoose/commits/4.13.21
- https://github.com/Automattic/mongoose/releases/tag/4.13.21
- https://github.com/Automattic/mongoose/commit/f88eb2524b65a68ff893c90a03c04f0913c1913e
- https://github.com/advisories/GHSA-8687-vv9j-hgph
Advisory URL: https://github.com/advisories/GHSA-8687-vv9j-hgph
BunknownJCVE-2019-17426j

pkg:npm/mongoose@5.4.01095078Eautomattic/mongoose vulnerable to Prototype pollution via Schema.path 0:öVulnerable Versions: <5.13.15
Recommendation: Upgrade to version 5.13.15 or later
Overview: Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment. Affected versions of this package are vulnerable to Prototype Pollution. The `Schema.path()` function is vulnerable to prototype pollution when setting the schema object. This vulnerability allows modification of the Object prototype and could be manipulated into a Denial of Service (DoS) attack.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2022-2564
- https://github.com/automattic/mongoose/commit/a45cfb6b0ce0067ae9794cfa80f7917e1fb3c6f8
- https://huntr.dev/bounties/055be524-9296-4b2f-b68d-6d5b810d1ddd
- https://github.com/Automattic/mongoose/blob/master/CHANGELOG.md
- https://github.com/Automattic/mongoose/blob/51e758541763b6f14569744ced15cc23ab8b50c6/lib/schema.js#L88-L141
- https://github.com/Automattic/mongoose/compare/6.4.5...6.4.6
- https://github.com/Automattic/mongoose/commit/99b418941e2fc974199b8e5bd9d382bb50bf680a
- https://github.com/advisories/GHSA-f825-f98c-gj3g
Advisory URL: https://github.com/advisories/GHSA-f825-f98c-gj3g
BunknownJCVE-2022-2564j©
è
pkg:npm/mongoose@5.4.01095080*Mongoose Prototype Pollution vulnerability 0:øVulnerable Versions: <5.13.20
Recommendation: Upgrade to version 5.13.20 or later
Overview: Prototype Pollution in GitHub repository automattic/mongoose prior to 7.3.3, 6.11.3, and 5.13.20.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2023-3696
- https://github.com/automattic/mongoose/commit/305ce4ff789261df7e3f6e72363d0703e025f80d
- https://huntr.dev/bounties/1eef5a72-f6ab-4f61-b31d-fc66f5b4b467
- https://github.com/Automattic/mongoose/commit/e29578d2ec18a68aeb4717d66dd5eb66bae53de1
- https://github.com/Automattic/mongoose/commit/f1efabf350522257364aa5c2cb36e441cf08f1a2
- https://github.com/Automattic/mongoose/releases/tag/7.3.3
- https://github.com/advisories/GHSA-9m93-w8w6-76hh
Advisory URL: https://github.com/advisories/GHSA-9m93-w8w6-76hh
BunknownJCVE-2023-3696j©
þ
pkg:npm/mongoose@5.4.01097158;Mongoose Vulnerable to Prototype Pollution in Schema Object 0:üVulnerable Versions: <5.13.15
Recommendation: Upgrade to version 5.13.15 or later
Overview: ### Description
Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment.

Affected versions of this package are vulnerable to Prototype Pollution. The `Schema.path()` function is vulnerable to prototype pollution when setting the `schema` object. This vulnerability allows modification of the Object prototype and could be manipulated into a Denial of Service (DoS) attack.

### Proof of Concept
```js
// poc.js
const mongoose = require('mongoose');
const schema = new mongoose.Schema();

malicious_payload = '__proto__.toString'

schema.path(malicious_payload, [String])

x = {}
console.log(x.toString()) // crashed (Denial of service (DoS) attack)
```

### Impact
This vulnerability can be manipulated to exploit other types of attacks, such as Denial of service (DoS), Remote Code Execution, or Property Injection.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2022-24304
- https://github.com/Automattic/mongoose/commit/a45cfb6b0ce0067ae9794cfa80f7917e1fb3c6f8
- https://github.com/Automattic/mongoose/blob/51e758541763b6f14569744ced15cc23ab8b50c6/lib/schema.js#L88-L141
- https://github.com/Automattic/mongoose/issues/12085
- https://github.com/Automattic/mongoose/commit/6a197316564742c0422309e1b5fecfa4faec126e
- https://huntr.dev/bounties/055be524-9296-4b2f-b68d-6d5b810d1ddd/
- https://github.com/advisories/GHSA-h8hf-x3f4-xwgp
Advisory URL: https://github.com/advisories/GHSA-h8hf-x3f4-xwgp
BunknownJCVE-2022-24304j©
ê
pkg:npm/async@2.6.11097691Prototype Pollution in async 0:ŠVulnerable Versions: >=2.0.0 <2.6.4
Recommendation: Upgrade to version 2.6.4 or later
Overview: A vulnerability exists in Async through 3.2.1 for 3.x and through 2.6.3 for 2.x (fixed in 3.2.2 and 2.6.4), which could let a malicious user obtain privileges via the `mapValues()` method.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2021-43138
- https://github.com/caolan/async/commit/e1ecdbf79264f9ab488c7799f4c76996d5dca66d
- https://github.com/caolan/async/blob/master/lib/internal/iterator.js
- https://github.com/caolan/async/blob/master/lib/mapValuesLimit.js
- https://github.com/caolan/async/pull/1828
- https://github.com/caolan/async/commit/8f7f90342a6571ba1c197d747ebed30c368096d2
- https://github.com/caolan/async/blob/v2.6.4/CHANGELOG.md#v264
- https://github.com/caolan/async/compare/v2.6.3...v2.6.4
- https://jsfiddle.net/oz5twjd9
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MTEUUTNIEBHGKUKKLNUZSV7IEP6IP3Q3
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UM6XJ73Q3NAM5KSGCOKJ2ZIA6GUWUJLK
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MTEUUTNIEBHGKUKKLNUZSV7IEP6IP3Q3
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UM6XJ73Q3NAM5KSGCOKJ2ZIA6GUWUJLK
- https://security.netapp.com/advisory/ntap-20240621-0006
- https://github.com/advisories/GHSA-fwr7-v2mv-hh25
Advisory URL: https://github.com/advisories/GHSA-fwr7-v2mv-hh25
BunknownJCVE-2021-43138j©


pkg:npm/axios@0.18.01090049/Axios vulnerable to Server-Side Request Forgery 0:œ	Vulnerable Versions: <0.21.1
Recommendation: Upgrade to version 0.21.1 or later
Overview: Axios NPM package 0.21.0 contains a Server-Side Request Forgery (SSRF) vulnerability where an attacker is able to bypass a proxy by providing a URL that responds with a redirect to a restricted host or IP address.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2020-28168
- https://github.com/axios/axios/issues/3369
- https://github.com/axios/axios/commit/c7329fefc890050edd51e40e469a154d0117fc55
- https://snyk.io/vuln/SNYK-JS-AXIOS-1038255
- https://www.npmjs.com/package/axios
- https://www.npmjs.com/advisories/1594
- https://lists.apache.org/thread.html/r954d80fd18e9dafef6e813963eb7e08c228151c2b6268ecd63b35d1f@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r25d53acd06f29244b8a103781b0339c5e7efee9099a4d52f0c230e4a@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/rdfd2901b8b697a3f6e2c9c6ecc688fd90d7f881937affb5144d61d6e@%3Ccommits.druid.apache.org%3E
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://github.com/advisories/GHSA-4w2v-q235-vp99
Advisory URL: https://github.com/advisories/GHSA-4w2v-q235-vp99
BunknownJCVE-2020-28168j–Á
pkg:npm/axios@0.18.01091722Denial of Service in axios 0:áVulnerable Versions: <=0.18.0
Recommendation: Upgrade to version 0.18.1 or later
Overview: Versions of `axios` prior to 0.18.1 are vulnerable to Denial of Service. If a request exceeds the `maxContentLength` property, the package prints an error but does not stop the request. This may cause high CPU usage and lead to Denial of Service.


## Recommendation

Upgrade to 0.18.1 or later.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2019-10742
- https://app.snyk.io/vuln/SNYK-JS-AXIOS-174505
- https://github.com/axios/axios/issues/1098
- https://github.com/axios/axios/pull/1485
- https://snyk.io/vuln/SNYK-JS-AXIOS-174505
- https://www.npmjs.com/advisories/880
- https://github.com/axios/axios/commit/acabfbdf00a58bb866c9d070e8a10d1d0dbeb572
- https://github.com/advisories/GHSA-42xw-2xvc-qx8m
Advisory URL: https://github.com/advisories/GHSA-42xw-2xvc-qx8m
BunknownJCVE-2019-10742jóŽ
pkg:npm/axios@0.18.01095000=axios Inefficient Regular Expression Complexity vulnerability 0:‹Vulnerable Versions: <0.21.2
Recommendation: Upgrade to version 0.21.2 or later
Overview: axios before v0.21.2 is vulnerable to Inefficient Regular Expression Complexity.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2021-3749
- https://github.com/axios/axios/commit/5b457116e31db0e88fede6c428e969e87f290929
- https://huntr.dev/bounties/1e8f07fc-c384-4ff9-8498-0690de2e8c31
- https://www.npmjs.com/package/axios
- https://lists.apache.org/thread.html/r075d464dce95cd13c03ff9384658edcccd5ab2983b82bfc72b62bb10@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r216f0fd0a3833856d6a6a1fada488cadba45f447d87010024328ccf2@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r3ae6d2654f92c5851bdb73b35e96b0e4e3da39f28ac7a1b15ae3aab8@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r4bf1b32983f50be00f9752214c1b53738b621be1c2b0dbd68c7f2391@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r7324ecc35b8027a51cb6ed629490fcd3b2d7cf01c424746ed5744bf1@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/r74d0b359408fff31f87445261f0ee13bdfcac7d66f6b8e846face321@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/ra15d63c54dc6474b29f72ae4324bcb03038758545b3ab800845de7a1@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/rc263bfc5b53afcb7e849605478d73f5556eb0c00d1f912084e407289@%3Ccommits.druid.apache.org%3E
- https://lists.apache.org/thread.html/rfa094029c959da0f7c8cd7dc9c4e59d21b03457bf0cedf6c93e1bb0a@%3Cdev.druid.apache.org%3E
- https://lists.apache.org/thread.html/rfc5c478053ff808671aef170f3d9fc9d05cc1fab8fb64431edc66103@%3Ccommits.druid.apache.org%3E
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://github.com/advisories/GHSA-cph5-m8f7-6c5x
Advisory URL: https://github.com/advisories/GHSA-cph5-m8f7-6c5x
BunknownJCVE-2021-3749jµ
®	
pkg:npm/axios@0.18.01097679.Axios Cross-Site Request Forgery Vulnerability 0:»Vulnerable Versions: >=0.8.1 <0.28.0
Recommendation: Upgrade to version 0.28.0 or later
Overview: An issue discovered in Axios 0.8.1 through 1.5.1 inadvertently reveals the confidential XSRF-TOKEN stored in cookies by including it in the HTTP header X-XSRF-TOKEN for every request made to any host allowing attackers to view sensitive information.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2023-45857
- https://github.com/axios/axios/issues/6006
- https://github.com/axios/axios/issues/6022
- https://github.com/axios/axios/pull/6028
- https://github.com/axios/axios/commit/96ee232bd3ee4de2e657333d4d2191cd389e14d0
- https://github.com/axios/axios/releases/tag/v1.6.0
- https://security.snyk.io/vuln/SNYK-JS-AXIOS-6032459
- https://github.com/axios/axios/pull/6091
- https://github.com/axios/axios/commit/2755df562b9c194fba6d8b609a383443f6a6e967
- https://github.com/axios/axios/releases/tag/v0.28.0
- https://security.netapp.com/advisory/ntap-20240621-0006
- https://github.com/advisories/GHSA-wf5p-g6vw-rhxx
Advisory URL: https://github.com/advisories/GHSA-wf5p-g6vw-rhxx
BunknownJCVE-2023-45857jàÂ'
pkg:npm/jquery@3.3.11094185%Potential XSS vulnerability in jQuery 0:Ù&Vulnerable Versions: >=1.2.0 <3.5.0
Recommendation: Upgrade to version 3.5.0 or later
Overview: ### Impact
Passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. `.html()`, `.append()`, and others) may execute untrusted code.

### Patches
This problem is patched in jQuery 3.5.0.

### Workarounds
To workaround the issue without upgrading, adding the following to your code:

```js
jQuery.htmlPrefilter = function( html ) {
	return html;
};
```

You need to use at least jQuery 1.12/2.2 or newer to be able to apply this workaround.

### References
https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
https://jquery.com/upgrade-guide/3.5/

### For more information
If you have any questions or comments about this advisory, search for a relevant issue in [the jQuery repo](https://github.com/jquery/jquery/issues). If you don't find an answer, open a new issue.
References:
- https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
- https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77
- https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
- https://jquery.com/upgrade-guide/3.5/
- https://nvd.nist.gov/vuln/detail/CVE-2020-11022
- https://security.netapp.com/advisory/ntap-20200511-0006/
- https://www.drupal.org/sa-core-2020-002
- https://www.debian.org/security/2020/dsa-4693
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VOE7P7APPRQKD4FGNHBKJPDY6FFCOH3W/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QPN2L2XVQGUA2V5HNQJWHK3APSK3VN7K/
- https://www.oracle.com/security-alerts/cpujul2020.html
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00067.html
- https://security.gentoo.org/glsa/202007-03
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00085.html
- https://lists.apache.org/thread.html/rdf44341677cf7eec7e9aa96dcf3f37ed709544863d619cca8c36f133@%3Ccommits.airflow.apache.org%3E
- https://github.com/advisories/GHSA-gxr4-xjj5-5px2
- https://www.npmjs.com/advisories/1518
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVKYXLWCLZBV2N7M46KYK4LVA5OXWPBY/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SFP4UK4EGP4AFH2MWYJ5A5Z4I7XVFQ6B/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SAPQVX3XDNPGFT26QAQ6AJIXZZBZ4CD4/
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://lists.apache.org/thread.html/r706cfbc098420f7113968cc377247ec3d1439bce42e679c11c609e2d@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/rbb448222ba62c430e21e13f940be4cb5cfc373cd3bce56b48c0ffa67@%3Cdev.flink.apache.org%3E
- http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00039.html
- https://lists.apache.org/thread.html/r49ce4243b4738dd763caeb27fa8ad6afb426ae3e8c011ff00b8b1f48@%3Cissues.flink.apache.org%3E
- https://www.tenable.com/security/tns-2020-10
- https://www.tenable.com/security/tns-2020-11
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://lists.apache.org/thread.html/r564585d97bc069137e64f521e68ba490c7c9c5b342df5d73c49a0760@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r8f70b0f65d6bedf316ecd899371fd89e65333bc988f6326d2956735c@%3Cissues.flink.apache.org%3E
- https://www.tenable.com/security/tns-2021-02
- https://lists.debian.org/debian-lts-announce/2021/03/msg00033.html
- http://packetstormsecurity.com/files/162159/jQuery-1.2-Cross-Site-Scripting.html
- https://lists.apache.org/thread.html/rede9cfaa756e050a3d83045008f84a62802fc68c17f2b4eabeaae5e4@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/ree3bd8ddb23df5fa4e372d11c226830ea3650056b1059f3965b3fce2@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r54565a8f025c7c4f305355fdfd75b68eca442eebdb5f31c2e7d977ae@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/re4ae96fa5c1a2fe71ccbb7b7ac1538bd0cb677be270a2bf6e2f8d108@%3Cissues.flink.apache.org%3E
- https://www.tenable.com/security/tns-2021-10
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://lists.apache.org/thread.html/r0483ba0072783c2e1bfea613984bfb3c86e73ba8879d780dc1cc7d36@%3Cissues.flink.apache.org%3E
- https://github.com/jquery/jquery/releases/tag/3.5.0
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://lists.debian.org/debian-lts-announce/2023/08/msg00040.html
- https://github.com/rubysec/ruby-advisory-db/blob/master/gems/jquery-rails/CVE-2020-11022.yml
Advisory URL: https://github.com/advisories/GHSA-gxr4-xjj5-5px2
BunknownJCVE-2020-11022jO·S
pkg:npm/jquery@3.3.11097145AXSS in jQuery as used in Drupal, Backdrop CMS, and other products 0:°RVulnerable Versions: >=1.1.4 <3.4.0
Recommendation: Upgrade to version 3.4.0 or later
Overview: jQuery from 1.1.4 until 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles `jQuery.extend(true, {}, ...)` because of `Object.prototype` pollution. If an unsanitized source object contained an enumerable `__proto__` property, it could extend the native `Object.prototype`.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2019-11358
- https://backdropcms.org/security/backdrop-sa-core-2019-009
- https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
- https://github.com/jquery/jquery/pull/4333
- https://snyk.io/vuln/SNYK-JS-JQUERY-174006
- https://www.drupal.org/sa-core-2019-006
- https://access.redhat.com/errata/RHSA-2019:3023
- https://access.redhat.com/errata/RHSA-2019:3024
- https://lists.apache.org/thread.html/08720ef215ee7ab3386c05a1a90a7d1c852bf0706f176a7816bf65fc@%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/519eb0fd45642dcecd9ff74cb3e71c20a4753f7d82e2f07864b5108f@%3Cdev.drill.apache.org%3E
- https://lists.apache.org/thread.html/5928aa293e39d248266472210c50f176cac1535220f2486e6a7fa844@%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/6097cdbd6f0a337bedd9bb5cc441b2d525ff002a96531de367e4259f@%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/88fb0362fd40e5b605ea8149f63241537b8b6fb5bfa315391fc5cbb7@%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/b0656d359c7d40ec9f39c8cc61bca66802ef9a2a12ee199f5b0c1442@%3Cdev.drill.apache.org%3E
- https://lists.apache.org/thread.html/b736d0784cf02f5a30fbb4c5902762a15ad6d47e17e2c5a17b7d6205@%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/ba79cf1658741e9f146e4c59b50aee56656ea95d841d358d006c18b6@%3Ccommits.roller.apache.org%3E
- https://lists.apache.org/thread.html/bcce5a9c532b386c68dab2f6b3ce8b0cc9b950ec551766e76391caa3@%3Ccommits.nifi.apache.org%3E
- https://lists.apache.org/thread.html/f9bc3e55f4e28d1dcd1a69aae6d53e609a758e34d2869b4d798e13cc@%3Cissues.drill.apache.org%3E
- https://lists.apache.org/thread.html/r38f0d1aa3c923c22977fe7376508f030f22e22c1379fbb155bf29766@%3Cdev.syncope.apache.org%3E
- https://lists.apache.org/thread.html/r7aac081cbddb6baa24b75e74abf0929bf309b176755a53e3ed810355@%3Cdev.flink.apache.org%3E
- https://lists.apache.org/thread.html/rac25da84ecdcd36f6de5ad0d255f4e967209bbbebddb285e231da37d@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/rca37935d661f4689cb4119f1b3b224413b22be161b678e6e6ce0c69b@%3Ccommits.nifi.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2019/05/msg00006.html
- https://lists.debian.org/debian-lts-announce/2019/05/msg00029.html
- https://lists.debian.org/debian-lts-announce/2020/02/msg00024.html
- https://www.debian.org/security/2019/dsa-4434
- https://www.debian.org/security/2019/dsa-4460
- https://www.synology.com/security/advisory/Synology_SA_19_19
- https://www.tenable.com/security/tns-2019-08
- https://www.tenable.com/security/tns-2020-02
- http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00006.html
- http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00025.html
- http://packetstormsecurity.com/files/152787/dotCMS-5.1.1-Vulnerable-Dependencies.html
- http://packetstormsecurity.com/files/153237/RetireJS-CORS-Issue-Script-Execution.html
- http://packetstormsecurity.com/files/156743/OctoberCMS-Insecure-Dependencies.html
- http://www.openwall.com/lists/oss-security/2019/06/03/2
- https://lists.apache.org/thread.html/r2041a75d3fc09dec55adfd95d598b38d22715303f65c997c054844c9@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r2baacab6e0acb5a2092eb46ae04fd6c3e8277b4fd79b1ffb7f3254fa@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r41b5bfe009c845f67d4f68948cc9419ac2d62e287804aafd72892b08@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r7e8ebccb7c022e41295f6fdb7b971209b83702339f872ddd8cf8bf73@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r7d64895cc4dff84d0becfc572b20c0e4bf9bfa7b10c6f5f73e783734@%3Cdev.storm.apache.org%3E
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601
- https://github.com/rails/jquery-rails/blob/master/CHANGELOG.md#434
- https://github.com/rubysec/ruby-advisory-db/blob/master/gems/jquery-rails/CVE-2019-11358.yml
- https://security.snyk.io/vuln/SNYK-DOTNET-JQUERY-450226
- https://access.redhat.com/errata/RHBA-2019:1570
- https://access.redhat.com/errata/RHSA-2019:1456
- https://access.redhat.com/errata/RHSA-2019:2587
- https://seclists.org/bugtraq/2019/Apr/32
- https://seclists.org/bugtraq/2019/Jun/12
- https://seclists.org/bugtraq/2019/May/18
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2020.html
- https://www.oracle.com/security-alerts/cpujan2020.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
- https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
- http://seclists.org/fulldisclosure/2019/May/10
- http://seclists.org/fulldisclosure/2019/May/11
- http://seclists.org/fulldisclosure/2019/May/13
- https://supportportal.juniper.net/s/article/2021-07-Security-Bulletin-Junos-OS-Multiple-J-Web-vulnerabilities-resolved-in-Junos-OS-21-2R1
- https://web.archive.org/web/20190824065237/http://www.securityfocus.com/bid/108023
- https://github.com/django/django/commit/34ec52269ade54af31a021b12969913129571a3f
- https://github.com/django/django/commit/95649bc08547a878cebfa1d019edec8cb1b80829
- https://github.com/django/django/commit/baaf187a4e354bf3976c51e2c83a0d2f8ee6e6ad
- https://lists.debian.org/debian-lts-announce/2023/08/msg00040.html
- http://www.securityfocus.com/bid/108023
- https://blog.jquery.com/2019/04/10/jquery-3-4-0-released
- https://lists.apache.org/thread.html/08720ef215ee7ab3386c05a1a90a7d1c852bf0706f176a7816bf65fc%40%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/519eb0fd45642dcecd9ff74cb3e71c20a4753f7d82e2f07864b5108f%40%3Cdev.drill.apache.org%3E
- https://lists.apache.org/thread.html/5928aa293e39d248266472210c50f176cac1535220f2486e6a7fa844%40%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/6097cdbd6f0a337bedd9bb5cc441b2d525ff002a96531de367e4259f%40%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/88fb0362fd40e5b605ea8149f63241537b8b6fb5bfa315391fc5cbb7%40%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/b0656d359c7d40ec9f39c8cc61bca66802ef9a2a12ee199f5b0c1442%40%3Cdev.drill.apache.org%3E
- https://lists.apache.org/thread.html/b736d0784cf02f5a30fbb4c5902762a15ad6d47e17e2c5a17b7d6205%40%3Ccommits.airflow.apache.org%3E
- https://lists.apache.org/thread.html/ba79cf1658741e9f146e4c59b50aee56656ea95d841d358d006c18b6%40%3Ccommits.roller.apache.org%3E
- https://lists.apache.org/thread.html/bcce5a9c532b386c68dab2f6b3ce8b0cc9b950ec551766e76391caa3%40%3Ccommits.nifi.apache.org%3E
- https://lists.apache.org/thread.html/f9bc3e55f4e28d1dcd1a69aae6d53e609a758e34d2869b4d798e13cc%40%3Cissues.drill.apache.org%3E
- https://lists.apache.org/thread.html/r2041a75d3fc09dec55adfd95d598b38d22715303f65c997c054844c9%40%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r2baacab6e0acb5a2092eb46ae04fd6c3e8277b4fd79b1ffb7f3254fa%40%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r38f0d1aa3c923c22977fe7376508f030f22e22c1379fbb155bf29766%40%3Cdev.syncope.apache.org%3E
- https://lists.apache.org/thread.html/r41b5bfe009c845f67d4f68948cc9419ac2d62e287804aafd72892b08%40%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r7aac081cbddb6baa24b75e74abf0929bf309b176755a53e3ed810355%40%3Cdev.flink.apache.org%3E
- https://lists.apache.org/thread.html/r7d64895cc4dff84d0becfc572b20c0e4bf9bfa7b10c6f5f73e783734%40%3Cdev.storm.apache.org%3E
- https://lists.apache.org/thread.html/r7e8ebccb7c022e41295f6fdb7b971209b83702339f872ddd8cf8bf73%40%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/rac25da84ecdcd36f6de5ad0d255f4e967209bbbebddb285e231da37d%40%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/rca37935d661f4689cb4119f1b3b224413b22be161b678e6e6ce0c69b%40%3Ccommits.nifi.apache.org%3E
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4UOAZIFCSZ3ENEFOR5IXX6NFAD3HV7FA
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5IABSKTYZ5JUGL735UKGXL5YPRYOPUYI
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KYH3OAGR2RTCHRA5NOKX2TES7SNQMWGO
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QV3PKZC3PQCO3273HAT76PAQZFBEO4KP
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RLXRX23725JL366CNZGJZ7AQQB7LHQ6F
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WZW27UCJ5CYFL4KFFFMYMIBNMIU2ALG5
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4UOAZIFCSZ3ENEFOR5IXX6NFAD3HV7FA
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5IABSKTYZ5JUGL735UKGXL5YPRYOPUYI
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KYH3OAGR2RTCHRA5NOKX2TES7SNQMWGO
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QV3PKZC3PQCO3273HAT76PAQZFBEO4KP
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RLXRX23725JL366CNZGJZ7AQQB7LHQ6F
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WZW27UCJ5CYFL4KFFFMYMIBNMIU2ALG5
- https://security.netapp.com/advisory/ntap-20190919-0001
- https://www.djangoproject.com/weblog/2019/jun/03/security-releases
- https://www.privacy-wise.com/mitigating-cve-2019-11358-in-old-versions-of-jquery
- https://github.com/advisories/GHSA-6c3j-c64m-qhgq
Advisory URL: https://github.com/advisories/GHSA-6c3j-c64m-qhgq
BunknownJCVE-2019-11358jO©
‹C
pkg:npm/jquery@3.3.11097311%Potential XSS vulnerability in jQuery 0:¢BVulnerable Versions: >=1.0.3 <3.5.0
Recommendation: Upgrade to version 3.5.0 or later
Overview: ### Impact
Passing HTML containing `<option>` elements from untrusted sources - even after sanitizing them - to one of jQuery's DOM manipulation methods (i.e. `.html()`, `.append()`, and others) may execute untrusted code.

### Patches
This problem is patched in jQuery 3.5.0.

### Workarounds
To workaround this issue without upgrading, use [DOMPurify](https://github.com/cure53/DOMPurify) with its `SAFE_FOR_JQUERY` option to sanitize the HTML string before passing it to a jQuery method.

### References
https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/

### For more information
If you have any questions or comments about this advisory, search for a relevant issue in [the jQuery repo](https://github.com/jquery/jquery/issues). If you don't find an answer, open a new issue.
References:
- https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6
- https://blog.jquery.com/2020/04/10/jquery-3-5-0-released
- https://nvd.nist.gov/vuln/detail/CVE-2020-11023
- https://www.drupal.org/sa-core-2020-002
- https://www.debian.org/security/2020/dsa-4693
- https://www.oracle.com/security-alerts/cpujul2020.html
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00067.html
- https://security.gentoo.org/glsa/202007-03
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00085.html
- https://lists.apache.org/thread.html/r0593393ca1e97b1e7e098fe69d414d6bd0a467148e9138d07e86ebbb@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/r094f435595582f6b5b24b66fedf80543aa8b1d57a3688fbcc21f06ec@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/r1fed19c860a0d470f2a3eded12795772c8651ff583ef951ddac4918c@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/r4aadb98086ca72ed75391f54167522d91489a0d0ae25b12baa8fc7c5@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/r6c4df3b33e625a44471009a172dabe6865faec8d8f21cac2303463b1@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/r6e97b37963926f6059ecc1e417721608723a807a76af41d4e9dbed49@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/r9c5fda81e4bca8daee305b4c03283dddb383ab8428a151d4cb0b3b15@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/ra32c7103ded9041c7c1cb8c12c8d125a6b2f3f3270e2937ef8417fac@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/ra374bb0299b4aa3e04edde01ebc03ed6f90cf614dad40dd428ce8f72@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/ra3c9219fcb0b289e18e9ec5a5ebeaa5c17d6b79a201667675af6721c@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/ra406b3adfcffcb5ce8707013bdb7c35e3ffc2776a8a99022f15274c6@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/rab82dd040f302018c85bd07d33f5604113573514895ada523c3401d9@%3Ccommits.hive.apache.org%3E
- https://lists.apache.org/thread.html/radcb2aa874a79647789f3563fcbbceaf1045a029ee8806b59812a8ea@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/rb25c3bc7418ae75cba07988dafe1b6912f76a9dd7d94757878320d61@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/rb69b7d8217c1a6a2100247a5d06ce610836b31e3f5d73fc113ded8e7@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/rd38b4185a797b324c8dd940d9213cf99fcdc2dbf1fc5a63ba7dee8c9@%3Cissues.hive.apache.org%3E
- https://lists.apache.org/thread.html/rda99599896c3667f2cc9e9d34c7b6ef5d2bbed1f4801e1d75a2b0679@%3Ccommits.nifi.apache.org%3E
- https://lists.apache.org/thread.html/rf1ba79e564fe7efc56aef7c986106f1cf67a3427d08e997e088e7a93@%3Cgitbox.hive.apache.org%3E
- https://lists.apache.org/thread.html/rf661a90a15da8da5922ba6127b3f5f8194d4ebec8855d60a0dd13248@%3Cdev.hive.apache.org%3E
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://lists.apache.org/thread.html/r706cfbc098420f7113968cc377247ec3d1439bce42e679c11c609e2d@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/rbb448222ba62c430e21e13f940be4cb5cfc373cd3bce56b48c0ffa67@%3Cdev.flink.apache.org%3E
- http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00039.html
- https://lists.apache.org/thread.html/r49ce4243b4738dd763caeb27fa8ad6afb426ae3e8c011ff00b8b1f48@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r07ab379471fb15644bf7a92e4a98cbc7df3cf4e736abae0cc7625fe6@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/r2c85121a47442036c7f8353a3724aa04f8ecdfda1819d311ba4f5330@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/r3702ede0ff83a29ba3eb418f6f11c473d6e3736baba981a8dbd9c9ef@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/r4dba67be3239b34861f1b9cfdf9dfb3a90272585dcce374112ed6e16@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/r55f5e066cc7301e3630ce90bbbf8d28c82212ae1f2d4871012141494@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/r9006ad2abf81d02a0ef2126bab5177987e59095b7194a487c4ea247c@%3Ccommits.felix.apache.org%3E
- https://lists.apache.org/thread.html/r9e0bd31b7da9e7403478d22652b8760c946861f8ebd7bd750844898e@%3Cdev.felix.apache.org%3E
- https://lists.apache.org/thread.html/rf0f8939596081d84be1ae6a91d6248b96a02d8388898c372ac807817@%3Cdev.felix.apache.org%3E
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://lists.apache.org/thread.html/r564585d97bc069137e64f521e68ba490c7c9c5b342df5d73c49a0760@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r8f70b0f65d6bedf316ecd899371fd89e65333bc988f6326d2956735c@%3Cissues.flink.apache.org%3E
- https://www.tenable.com/security/tns-2021-02
- https://lists.debian.org/debian-lts-announce/2021/03/msg00033.html
- http://packetstormsecurity.com/files/162160/jQuery-1.0.3-Cross-Site-Scripting.html
- https://lists.apache.org/thread.html/rede9cfaa756e050a3d83045008f84a62802fc68c17f2b4eabeaae5e4@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/ree3bd8ddb23df5fa4e372d11c226830ea3650056b1059f3965b3fce2@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/r54565a8f025c7c4f305355fdfd75b68eca442eebdb5f31c2e7d977ae@%3Cissues.flink.apache.org%3E
- https://lists.apache.org/thread.html/re4ae96fa5c1a2fe71ccbb7b7ac1538bd0cb677be270a2bf6e2f8d108@%3Cissues.flink.apache.org%3E
- https://www.tenable.com/security/tns-2021-10
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://lists.apache.org/thread.html/r0483ba0072783c2e1bfea613984bfb3c86e73ba8879d780dc1cc7d36@%3Cissues.flink.apache.org%3E
- https://github.com/jquery/jquery/releases/tag/3.5.0
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://github.com/rubysec/ruby-advisory-db/blob/master/gems/jquery-rails/CVE-2020-11023.yml
- https://security.snyk.io/vuln/SNYK-DOTNET-JQUERY-565440
- https://lists.debian.org/debian-lts-announce/2023/08/msg00040.html
- https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SFP4UK4EGP4AFH2MWYJ5A5Z4I7XVFQ6B
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SAPQVX3XDNPGFT26QAQ6AJIXZZBZ4CD4
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QPN2L2XVQGUA2V5HNQJWHK3APSK3VN7K
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVKYXLWCLZBV2N7M46KYK4LVA5OXWPBY
- https://snyk.io/vuln/SNYK-JS-JQUERY-565129
- https://security.netapp.com/advisory/ntap-20230725-0003
- https://security.netapp.com/advisory/ntap-20200511-0006
- https://jquery.com/upgrade-guide/3.5
- https://github.com/rubysec/ruby-advisory-db/blob/master/gems/jquery-rails/CVE-2020-23064.yml
- https://github.com/rails/jquery-rails/blob/v4.4.0/vendor/assets/javascripts/jquery3.js#L6162
- https://github.com/rails/jquery-rails/blob/v4.3.5/vendor/assets/javascripts/jquery3.js#L5979
- https://github.com/rails/jquery-rails/blob/master/CHANGELOG.md#440
- https://github.com/rails/jquery-rails/blob/master/CHANGELOG.md#410
- https://github.com/advisories/GHSA-jpcq-cgw6-v4j6
Advisory URL: https://github.com/advisories/GHSA-jpcq-cgw6-v4j6
BunknownJCVE-2020-11023jOÕ
pkg:npm/lodash@4.17.1110945006Regular Expression Denial of Service (ReDoS) in lodash 0:ÖVulnerable Versions: <4.17.21
Recommendation: Upgrade to version 4.17.21 or later
Overview: All versions of package lodash prior to 4.17.21 are vulnerable to Regular Expression Denial of Service (ReDoS) via the `toNumber`, `trim` and `trimEnd` functions. 

Steps to reproduce (provided by reporter Liyuan Chen):
```js
var lo = require('lodash');

function build_blank(n) {
    var ret = "1"
    for (var i = 0; i < n; i++) {
        ret += " "
    }
    return ret + "1";
}
var s = build_blank(50000) var time0 = Date.now();
lo.trim(s) 
var time_cost0 = Date.now() - time0;
console.log("time_cost0: " + time_cost0);
var time1 = Date.now();
lo.toNumber(s) var time_cost1 = Date.now() - time1;
console.log("time_cost1: " + time_cost1);
var time2 = Date.now();
lo.trimEnd(s);
var time_cost2 = Date.now() - time2;
console.log("time_cost2: " + time_cost2);
```
References:
- https://nvd.nist.gov/vuln/detail/CVE-2020-28500
- https://github.com/lodash/lodash/pull/5065
- https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7
- https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8
- https://security.netapp.com/advisory/ntap-20210312-0006/
- https://snyk.io/vuln/SNYK-JS-LODASH-1018905
- https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a
- https://github.com/advisories/GHSA-29mw-wpgm-hmr9
Advisory URL: https://github.com/advisories/GHSA-29mw-wpgm-hmr9
BunknownJCVE-2020-28500jµ
´
pkg:npm/lodash@4.17.111096305Prototype Pollution in lodash 0:Ï
Vulnerable Versions: >=3.7.0 <4.17.19
Recommendation: Upgrade to version 4.17.19 or later
Overview: Versions of lodash prior to 4.17.19 are vulnerable to Prototype Pollution. The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` allow a malicious user to modify the prototype of Object if the property identifiers are user-supplied. Being affected by this issue requires manipulating objects based on user-provided property values or arrays.

This vulnerability causes the addition or modification of an existing property that will exist on all objects and may lead to Denial of Service or Code Execution under specific circumstances.
References:
- https://github.com/lodash/lodash/issues/4744
- https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12
- https://nvd.nist.gov/vuln/detail/CVE-2020-8203
- https://hackerone.com/reports/712065
- https://github.com/lodash/lodash/issues/4874
- https://github.com/github/advisory-database/pull/2884
- https://hackerone.com/reports/864701
- https://github.com/lodash/lodash/wiki/Changelog#v41719
- https://web.archive.org/web/20210914001339/https://github.com/lodash/lodash/issues/4744
- https://security.netapp.com/advisory/ntap-20200724-0006/
- https://github.com/advisories/GHSA-p6mc-m468-83gw
Advisory URL: https://github.com/advisories/GHSA-p6mc-m468-83gw
BunknownJCVE-2020-8203j‚©
œ
pkg:npm/lodash@4.17.111096996Command Injection in lodash 0:º
Vulnerable Versions: <4.17.21
Recommendation: Upgrade to version 4.17.21 or later
Overview: `lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2021-23337
- https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c
- https://snyk.io/vuln/SNYK-JS-LODASH-1040724
- https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851
- https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851
- https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://security.netapp.com/advisory/ntap-20210312-0006
- https://github.com/advisories/GHSA-35jh-r3h4-6jhm
Advisory URL: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
BunknownJCVE-2021-23337jM^å	
pkg:npm/lodash@4.17.111097140Prototype Pollution in lodash 0:€	Vulnerable Versions: <4.17.12
Recommendation: Upgrade to version 4.17.12 or later
Overview: Versions of `lodash` before 4.17.12 are vulnerable to Prototype Pollution.  The function `defaultsDeep` allows a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}` causing the addition or modification of an existing property that will exist on all objects.

## Recommendation

Update to version 4.17.12 or later.
References:
- https://github.com/lodash/lodash/pull/4336
- https://nvd.nist.gov/vuln/detail/CVE-2019-10744
- https://snyk.io/vuln/SNYK-JS-LODASH-450202
- https://www.npmjs.com/advisories/1065
- https://access.redhat.com/errata/RHSA-2019:3024
- https://security.netapp.com/advisory/ntap-20191004-0005/
- https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp;utm_medium=RSS
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp%3Butm_medium=RSS
- https://github.com/advisories/GHSA-jf85-cpcp-j695
Advisory URL: https://github.com/advisories/GHSA-jf85-cpcp-j695
BunknownJCVE-2019-10744j©
ã
pkg:npm/moment@2.22.21095072AMoment.js vulnerable to Inefficient Regular Expression Complexity 0:ÚVulnerable Versions: >=2.18.0 <2.29.4
Recommendation: Upgrade to version 2.29.4 or later
Overview: ### Impact

* using string-to-date parsing in moment (more specifically rfc2822 parsing, which is tried by default) has quadratic (N^2) complexity on specific inputs
* noticeable slowdown is observed with inputs above 10k characters
* users who pass user-provided strings without sanity length checks to moment constructor are vulnerable to (Re)DoS attacks

### Patches
The problem is patched in 2.29.4, the patch can be applied to all affected versions with minimal tweaking.

### Workarounds
In general, given the proliferation of ReDoS attacks, it makes sense to limit the length of the user input to something sane, like 200 characters or less. I haven't seen legitimate cases of date-time strings longer than that, so all moment users who do pass a user-originating string to constructor are encouraged to apply such a rudimentary filter, that would help with this but also most future ReDoS vulnerabilities.

### References
There is an excellent writeup of the issue here: https://github.com/moment/moment/pull/6015#issuecomment-1152961973=

### Details
The issue is rooted in the code that removes legacy comments (stuff inside parenthesis) from strings during rfc2822 parsing. `moment("(".repeat(500000))` will take a few minutes to process, which is unacceptable.
References:
- https://github.com/moment/moment/security/advisories/GHSA-wc69-rhjr-hc9g
- https://github.com/moment/moment/pull/6015#issuecomment-1152961973
- https://github.com/moment/moment/commit/9a3b5894f3d5d602948ac8a02e4ee528a49ca3a3
- https://nvd.nist.gov/vuln/detail/CVE-2022-31129
- https://huntr.dev/bounties/f0952b67-f2ff-44a9-a9cd-99e0a87cb633/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6QIO6YNLTK2T7SPKDS4JEL45FANLNC2Q/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ORJX2LF6KMPIHP6B2P6KZIVKMLE3LVJ5/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IWY24RJA3SBJGA5N4CU4VBPHJPPPJL5O/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZMX5YHELQVCGKKQVFXIYOTBMN23YYSRO/
- https://security.netapp.com/advisory/ntap-20221014-0003/
- https://lists.debian.org/debian-lts-announce/2023/01/msg00035.html
- https://github.com/moment/moment/pull/6015/commits/4bbb9f3ccbe231de40207503f344fe5ce97584f4
- https://github.com/moment/moment/pull/6015/commits/bfd4f2375d5c1a2106246721d693a9611dddfbfe
- https://github.com/moment/moment/pull/6015/commits/dc0d180e90d8a84f7ff13572363330a22b3ea504
- https://github.com/advisories/GHSA-wc69-rhjr-hc9g
Advisory URL: https://github.com/advisories/GHSA-wc69-rhjr-hc9g
BunknownJCVE-2022-31129jµ
Â
pkg:npm/moment@2.22.210950835Path Traversal: 'dir/../../filename' in moment.locale 0:ÇVulnerable Versions: <2.29.2
Recommendation: Upgrade to version 2.29.2 or later
Overview: ### Impact
This vulnerability impacts npm (server) users of moment.js, especially if user provided locale string, eg `fr` is directly used to switch moment locale.

### Patches
This problem is patched in 2.29.2, and the patch can be applied to all affected versions (from 1.0.1 up until 2.29.1, inclusive).

### Workarounds
Sanitize user-provided locale name before passing it to moment.js.

### References
_Are there any links users can visit to find out more?_

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [moment repo](https://github.com/moment/moment)

References:
- https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4
- https://nvd.nist.gov/vuln/detail/CVE-2022-24785
- https://github.com/moment/moment/commit/4211bfc8f15746be4019bba557e29a7ba83d54c5
- https://www.tenable.com/security/tns-2022-09
- https://security.netapp.com/advisory/ntap-20220513-0006/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6QIO6YNLTK2T7SPKDS4JEL45FANLNC2Q/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ORJX2LF6KMPIHP6B2P6KZIVKMLE3LVJ5/
- https://lists.debian.org/debian-lts-announce/2023/01/msg00035.html
- https://github.com/advisories/GHSA-8hfj-j24r-96c4
Advisory URL: https://github.com/advisories/GHSA-8hfj-j24r-96c4
BunknownJCVE-2022-24785jº
pkg:npm/qs@6.5.21096470$qs vulnerable to Prototype Pollution 0:ÕVulnerable Versions: >=6.5.0 <6.5.3
Recommendation: Upgrade to version 6.5.3 or later
Overview: qs before 6.10.3 allows attackers to cause a Node process hang because an `__ proto__` key can be used. In many typical web framework use cases, an unauthenticated remote attacker can place the attack payload in the query string of the URL that is used to visit the application, such as `a[__proto__]=b&a[__proto__]&a[length]=100000000`. The fix was backported to qs 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, and 6.2.4.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2022-24999
- https://github.com/ljharb/qs/pull/428
- https://github.com/n8tz/CVE-2022-24999
- https://github.com/ljharb/qs/commit/4310742efbd8c03f6495f07906b45213da0a32ec
- https://github.com/ljharb/qs/commit/727ef5d34605108acb3513f72d5435972ed15b68
- https://github.com/ljharb/qs/commit/73205259936317b40f447c5cdb71c5b341848e1b
- https://github.com/ljharb/qs/commit/8b4cc14cda94a5c89341b77e5fe435ec6c41be2d
- https://github.com/ljharb/qs/commit/ba24e74dd17931f825adb52f5633e48293b584e1
- https://github.com/ljharb/qs/commit/e799ba57e573a30c14b67c1889c7c04d508b9105
- https://github.com/ljharb/qs/commit/ed0f5dcbef4b168a8ae299d78b1e4a2e9b1baf1f
- https://github.com/ljharb/qs/commit/f945393cfe442fe8c6e62b4156fd35452c0686ee
- https://github.com/ljharb/qs/commit/fc3682776670524a42e19709ec4a8138d0d7afda
- https://github.com/expressjs/express/releases/tag/4.17.3
- https://lists.debian.org/debian-lts-announce/2023/01/msg00039.html
- https://github.com/advisories/GHSA-hrpp-h998-j3pp
Advisory URL: https://github.com/advisories/GHSA-hrpp-h998-j3pp
BunknownJCVE-2022-24999j©
º
pkg:npm/qs@6.5.21096470$qs vulnerable to Prototype Pollution 0:ÕVulnerable Versions: >=6.5.0 <6.5.3
Recommendation: Upgrade to version 6.5.3 or later
Overview: qs before 6.10.3 allows attackers to cause a Node process hang because an `__ proto__` key can be used. In many typical web framework use cases, an unauthenticated remote attacker can place the attack payload in the query string of the URL that is used to visit the application, such as `a[__proto__]=b&a[__proto__]&a[length]=100000000`. The fix was backported to qs 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, and 6.2.4.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2022-24999
- https://github.com/ljharb/qs/pull/428
- https://github.com/n8tz/CVE-2022-24999
- https://github.com/ljharb/qs/commit/4310742efbd8c03f6495f07906b45213da0a32ec
- https://github.com/ljharb/qs/commit/727ef5d34605108acb3513f72d5435972ed15b68
- https://github.com/ljharb/qs/commit/73205259936317b40f447c5cdb71c5b341848e1b
- https://github.com/ljharb/qs/commit/8b4cc14cda94a5c89341b77e5fe435ec6c41be2d
- https://github.com/ljharb/qs/commit/ba24e74dd17931f825adb52f5633e48293b584e1
- https://github.com/ljharb/qs/commit/e799ba57e573a30c14b67c1889c7c04d508b9105
- https://github.com/ljharb/qs/commit/ed0f5dcbef4b168a8ae299d78b1e4a2e9b1baf1f
- https://github.com/ljharb/qs/commit/f945393cfe442fe8c6e62b4156fd35452c0686ee
- https://github.com/ljharb/qs/commit/fc3682776670524a42e19709ec4a8138d0d7afda
- https://github.com/expressjs/express/releases/tag/4.17.3
- https://lists.debian.org/debian-lts-announce/2023/01/msg00039.html
- https://github.com/advisories/GHSA-hrpp-h998-j3pp
Advisory URL: https://github.com/advisories/GHSA-hrpp-h998-j3pp
BunknownJCVE-2022-24999j©
­
pkg:npm/express@4.16.41096820*Express.js Open Redirect in malformed URLs 0:ºVulnerable Versions: <4.19.2
Recommendation: Upgrade to version 4.19.2 or later
Overview: ### Impact

Versions of Express.js prior to 4.19.2 and pre-release alpha and beta versions before 5.0.0-beta.3 are affected by an open redirect vulnerability using malformed URLs.

When a user of Express performs a redirect using a user-provided URL Express performs an encode [using `encodeurl`](https://github.com/pillarjs/encodeurl) on the contents before passing it to the `location` header. This can cause malformed URLs to be evaluated in unexpected ways by common redirect allow list implementations in Express applications, leading to an Open Redirect via bypass of a properly implemented allow list.

The main method impacted is `res.location()` but this is also called from within `res.redirect()`.

### Patches

https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd
https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94

An initial fix went out with `express@4.19.0`, we then patched a feature regression in `4.19.1` and added improved handling for the bypass in `4.19.2`.

### Workarounds

The fix for this involves pre-parsing the url string with either `require('node:url').parse` or `new URL`. These are steps you can take on your own before passing the user input string to `res.location` or `res.redirect`.

### References

https://github.com/expressjs/express/pull/5539
https://github.com/koajs/koa/issues/1800
https://expressjs.com/en/4x/api.html#res.location
References:
- https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc
- https://github.com/koajs/koa/issues/1800
- https://github.com/expressjs/express/pull/5539
- https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd
- https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94
- https://expressjs.com/en/4x/api.html#res.location
- https://nvd.nist.gov/vuln/detail/CVE-2024-29041
- https://github.com/advisories/GHSA-rv95-896h-c2vc
Advisory URL: https://github.com/advisories/GHSA-rv95-896h-c2vc
BunknownJCVE-2024-29041jÙ†
é
pkg:npm/angular@1.6.610874466XSS via JQLite DOM manipulation functions in AngularJS 0:þVulnerable Versions: <1.8.0
Recommendation: Upgrade to version 1.8.0 or later
Overview: ### Summary
XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to `JQLite` methods like `JQLite.prepend`, `JQLite.after`, `JQLite.append`, `JQLite.replaceWith`, `JQLite.append`, `new JQLite` and `angular.element`.

### Description

JQLite (DOM manipulation library that's part of AngularJS) manipulates input HTML before inserting it to the DOM in `jqLiteBuildFragment`.

One of the modifications performed [expands an XHTML self-closing tag](https://github.com/angular/angular.js/blob/418355f1cf9a9a9827ae81d257966e6acfb5623a/src/jqLite.js#L218).

If `jqLiteBuildFragment` is called (e.g. via `new JQLite(aString)`) with user-controlled HTML string that was sanitized (e.g. with [DOMPurify](https://github.com/cure53/DOMPurify)), the transformation done by JQLite may modify some forms of an inert, sanitized payload into a payload containing JavaScript - and trigger an XSS when the payload is inserted into DOM.

This is similar to a bug in jQuery `htmlPrefilter` function that was [fixed in 3.5.0](https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/).

### Proof of concept

```javascript
const inertPayloadÂ =Â `<div><style><style/><img src=x onerror="alert(1337)"/>`Â 
```
Note that the style element is not closed and `<img` would be a text node inside the style if inserted into the DOM as-is.
As such, some HTML sanitizers would leave the `<img` as is without processing it and stripping the `onerror` attribute.

```javascript
angular.element(document).append(inertPayload);
```
This will alert, as `<style/>` will be replaced with `<style></style>` before adding it to the DOM, closing the style element early and reactivating `img`.

### Patches
The issue is patched in `JQLite` bundled with angular 1.8.0. AngularJS users using JQuery should upgrade JQuery to 3.5.0, as a similar vulnerability [affects jQuery <3.5.0](https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2).

### Workarounds
Changing sanitizer configuration not to allow certain tag grouping (e.g. `<option><style></option>`) or inline style elements may stop certain exploitation vectors, but it's uncertain if all possible exploitation vectors would be covered. Upgrade of AngularJS to 1.8.0 is recommended.

### References
https://github.com/advisories/GHSA-mhp6-pxh8-r675
https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6
https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
https://snyk.io/vuln/SNYK-JS-ANGULAR-570058
References:
- https://github.com/google/security-research/security/advisories/GHSA-5cp4-xmrw-59wf
- https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
- https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6
- https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
- https://github.com/advisories/GHSA-mhp6-pxh8-r675
- https://snyk.io/vuln/SNYK-JS-ANGULAR-570058
- https://github.com/advisories/GHSA-5cp4-xmrw-59wf
Advisory URL: https://github.com/advisories/GHSA-5cp4-xmrw-59wf
BunknownjOÿ
pkg:npm/angular@1.6.61089079Prototype Pollution in angular 0:˜Vulnerable Versions: <1.7.9
Recommendation: Upgrade to version 1.7.9 or later
Overview: Versions of `angular ` prior to 1.7.9 are vulnerable to prototype pollution. The deprecated API function `merge()` does not restrict the modification of an Object's prototype in the , which may allow an attacker to add or modify an existing property that will exist on all objects.




## Recommendation

Upgrade to version 1.7.9 or later. The function was already deprecated and upgrades are not expected to break functionality.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2019-10768
- https://github.com/angular/angular.js/commit/add78e62004e80bb1e16ab2dfe224afa8e513bc3
- https://snyk.io/vuln/SNYK-JS-ANGULAR-534884
- https://lists.apache.org/thread.html/rca37935d661f4689cb4119f1b3b224413b22be161b678e6e6ce0c69b@%3Ccommits.nifi.apache.org%3E
- https://github.com/angular/angular.js/pull/16913
- https://www.npmjs.com/advisories/1343
- https://github.com/advisories/GHSA-89mq-4x47-5v83
Advisory URL: https://github.com/advisories/GHSA-89mq-4x47-5v83
BunknownJCVE-2019-10768j“©
Ø
pkg:npm/angular@1.6.61093555Cross site scripting in Angular 0:õVulnerable Versions: <1.8.0
Recommendation: Upgrade to version 1.8.0 or later
Overview: angular.js prior to 1.8.0 allows cross site scripting. The regex-based input HTML replacement may turn sanitized code into unsanitized one. Wrapping `<option>` elements in `<select>` ones changes parsing behavior, leading to possibly unsanitizing code.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2020-7676
- https://github.com/angular/angular.js/pull/17028
- https://snyk.io/vuln/SNYK-JS-ANGULAR-570058
- https://lists.apache.org/thread.html/r198985c02829ba8285ed4f9b1de54a33b5f31b08bb38ac51fc86961b@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r3f05cfd587c774ea83c18e59eda9fa37fa9bbf3421484d4ee1017a20@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r446c297cd6cda2bd7e345c9b0741d7f611df89902e5d515848c6f4b1@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r455ebd83a1c69ae8fd897560534a079c70a483dbe1e75504f1ca499b@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r57383582dcad2305430321589dfaca6793f5174c55da6ce8d06fbf9b@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r79e3feaaf87b81e80da0e17a579015f6dcb94c95551ced398d50c8d7@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/r80f210a5f4833d59c5d3de17dd7312f9daba0765ec7d4052469f13f1@%3Cozone-commits.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/rb6423268b25db0f800359986867648e11dbd38e133b9383e85067f02@%3Cozone-issues.hadoop.apache.org%3E
- https://lists.apache.org/thread.html/rda99599896c3667f2cc9e9d34c7b6ef5d2bbed1f4801e1d75a2b0679@%3Ccommits.nifi.apache.org%3E
- https://lists.apache.org/thread.html/rfa2b19d01d10a8637dc319a7d5994c3dbdb88c0a8f9a21533403577a@%3Cozone-issues.hadoop.apache.org%3E
- https://github.com/angular/angular.js/commit/2df43c07779137d1bddf7f3b282a1287a8634acd
- https://github.com/advisories/GHSA-mhp6-pxh8-r675
Advisory URL: https://github.com/advisories/GHSA-mhp6-pxh8-r675
BunknownJCVE-2020-7676jO§
pkg:npm/angular@1.6.610935741Angular (deprecated package) Cross-site Scripting 0:±Vulnerable Versions: <=1.8.3
Recommendation: None
Overview: All versions of package angular are vulnerable to Cross-site Scripting (XSS) due to insecure page caching in the Internet Explorer browser, which allows interpolation of `<textarea>` elements.

NPM package [angular](https://www.npmjs.com/package/angular) is deprecated. Those who want to receive security updates should use the actively maintained package [@angular/core](https://www.npmjs.com/package/@angular/core).
References:
- https://nvd.nist.gov/vuln/detail/CVE-2022-25869
- https://glitch.com/edit/%23%21/angular-repro-textarea-xss
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-2949783
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBANGULAR-2949784
- https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-2949782
- https://snyk.io/vuln/SNYK-JS-ANGULAR-2949781
- https://github.com/advisories/GHSA-prc3-vjfx-vhm9
Advisory URL: https://github.com/advisories/GHSA-prc3-vjfx-vhm9
BunknownJCVE-2022-25869jO¡

pkg:npm/angular@1.6.61094512Yangular vulnerable to regular expression denial of service via the angular.copy() utility 0:‚	Vulnerable Versions: <=1.8.3
Recommendation: None
Overview: All versions of the package angular are vulnerable to Regular Expression Denial of Service (ReDoS) via the angular.copy() utility function due to the usage of an insecure regular expression. Exploiting this vulnerability is possible by a large carefully-crafted input, which can result in catastrophic backtracking.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2023-26116
- https://security.snyk.io/vuln/SNYK-JS-ANGULAR-3373044
- https://stackblitz.com/edit/angularjs-vulnerability-angular-copy-redos
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-5406320
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBANGULAR-5406322
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-5406321
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OQWJLE5WE33WNMA54XSJIDXBRK2KL3XJ/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UDKFLKJ6VZKL52AFVW2OVZRMJWHMW55K/
- https://github.com/advisories/GHSA-2vrf-hf26-jrp5
Advisory URL: https://github.com/advisories/GHSA-2vrf-hf26-jrp5
BunknownJCVE-2023-26116jµ
›

pkg:npm/angular@1.6.61094513Tangular vulnerable to regular expression denial of service via the $resource service 0:	Vulnerable Versions: <=1.8.3
Recommendation: None
Overview: All versions of the package angular are vulnerable to Regular Expression Denial of Service (ReDoS) via the $resource service due to the usage of an insecure regular expression. Exploiting this vulnerability is possible by a large carefully-crafted input, which can result in catastrophic backtracking.
References:
- https://nvd.nist.gov/vuln/detail/CVE-2023-26117
- https://security.snyk.io/vuln/SNYK-JS-ANGULAR-3373045
- https://stackblitz.com/edit/angularjs-vulnerability-resource-trailing-slashes-redos
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-5406323
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBANGULAR-5406325
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-5406324
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OQWJLE5WE33WNMA54XSJIDXBRK2KL3XJ/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UDKFLKJ6VZKL52AFVW2OVZRMJWHMW55K/
- https://github.com/advisories/GHSA-2qqx-w9hr-q5gx
Advisory URL: https://github.com/advisories/GHSA-2qqx-w9hr-q5gx
BunknownJCVE-2023-26117jµ
É

pkg:npm/angular@1.6.61094514]angular vulnerable to regular expression denial of service via the <input type="url"> element 0:¦	Vulnerable Versions: <=1.8.3
Recommendation: None
Overview: All versions of the package angular are vulnerable to Regular Expression Denial of Service (ReDoS) via the <input type="url"> element due to the usage of an insecure regular expression in the input[url] functionality. Exploiting this vulnerability is possible by a large carefully-crafted input, which can result in catastrophic backtracking. 
References:
- https://nvd.nist.gov/vuln/detail/CVE-2023-26118
- https://security.snyk.io/vuln/SNYK-JS-ANGULAR-3373046
- https://stackblitz.com/edit/angularjs-vulnerability-inpur-url-validation-redos
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-5406326
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBANGULAR-5406328
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-5406327
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OQWJLE5WE33WNMA54XSJIDXBRK2KL3XJ/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UDKFLKJ6VZKL52AFVW2OVZRMJWHMW55K/
- https://github.com/advisories/GHSA-qwqh-hm9m-p5hr
Advisory URL: https://github.com/advisories/GHSA-qwqh-hm9m-p5hr
BunknownJCVE-2023-26118jµ
Ü	
pkg:npm/angular@1.6.61097291>angular vulnerable to super-linear runtime due to backtracking 0:ØVulnerable Versions: >=1.3.0 <=1.8.3
Recommendation: None
Overview: This affects versions of the package angular from 1.3.0. A regular expression used to split the value of the ng-srcset directive is vulnerable to super-linear runtime due to backtracking. With a large carefully-crafted input, this can result in catastrophic backtracking and cause a denial of service. 


**Note:**

This package is EOL and will not receive any updates to address this issue. Users should migrate to [@angular/core](https://www.npmjs.com/package/@angular/core).
References:
- https://nvd.nist.gov/vuln/detail/CVE-2024-21490
- https://security.snyk.io/vuln/SNYK-JS-ANGULAR-6091113
- https://stackblitz.com/edit/angularjs-vulnerability-ng-srcset-redos
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-6241746
- https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-6241747
- https://support.herodevs.com/hc/en-us/articles/25715686953485-CVE-2024-21490-AngularJS-Regular-Expression-Denial-of-Service-ReDoS
- https://github.com/advisories/GHSA-4w4v-5hc9-xrr2
Advisory URL: https://github.com/advisories/GHSA-4w4v-5hc9-xrr2
BunknownJCVE-2024-21490jµ
