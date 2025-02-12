package testdata

var CheckmarxOut = `
<?xml version="1.0" encoding="UTF-8"?>

<flaws>
    <metaData
        appID="165072" appName="WebgoatMay5" componentName="WebGoat"
        date="Monday, January 6, 2020 5:00:34 AM" releaseName="CX" sourceName="Checkmarx"
        sourceDesc="Checkmarx" />

    <flaw>
        <id>165072-WebGoat-Checkmarx-1539227441</id>
        <status>Recurrent</status>
        <issueDescription>
            - File: /some/target, Line:2, Column:
            22, Name:t, Code: } catch (Throwable t)
            - File: /some/target, Line:3, Column: 4,
            Name:t, Code: t.printStackTrace();
            - File: /some/target, Line:4, Column:
            21, Name:printStackTrace, Code: t.printStackTrace();</issueDescription>
        <remediationDesc />
        <exploitDesc />
        <issueRecommendation />
        <componentName>WebGoat</componentName>
        <module />
        <apiName />
        <vulnerabilityType>209</vulnerabilityType>
        <classification />
        <severity>High</severity>
        <fileName>/some/target</fileName>
        <lineNumber>2</lineNumber>
        <srcContext>WebGoatProd/JavaSource/org/owasp/webgoat/</srcContext>
        <defectInfo />
        <notes />
        <trace />
        <callerName />
        <findingCodeRegion />
        <dateFirstOccurrence />
        <issueBornDate />
        <issueName />
        <kBReference />
        <cVSSScore />
        <relatedExploitRange />
        <attackComplexity />
        <levelofAuthenticationNeeded />
        <confidentialityImpact />
        <integrityImpact />
        <availabilityImpact />
        <collateralDamagePotential />
        <targetDistribution />
        <confidentialityRequirement />
        <integrityRequirement />
        <availabilityRequirement />
        <availabilityofExploit />
        <typeofFixAvailable />
        <levelofVerificationthatVulnerabilityExist />
        <cVSSEquation />
    </flaw>
  
	<flaw>
	<id>165072-WebGoat-Checkmarx--366645893</id>
	<status>Recurrent</status>
	<issueDescription>
		- File: /some/target, Line:2, Column:
		23, Name:thr, Code: } catch (Throwable thr)
		- File: /some/target, Line:3, Column: 5,
		Name:thr, Code: thr.printStackTrace();
		- File: /some/target, Line:4, Column:
		24, Name:printStackTrace, Code: thr.printStackTrace();</issueDescription>
	<remediationDesc />
	<exploitDesc />
	<issueRecommendation />
	<componentName>WebGoat</componentName>
	<module />
	<apiName />
	<vulnerabilityType>210</vulnerabilityType>
	<classification />
	<severity>High</severity>
	<fileName>/some/target</fileName>
	<lineNumber>2</lineNumber>
	<srcContext>WebGoatProd/JavaSource/org/owasp/webgoat/</srcContext>
	<defectInfo />
	<notes />
	<trace />
	<callerName />
	<findingCodeRegion />
	<dateFirstOccurrence />
	<issueBornDate />
	<issueName />
	<kBReference />
	<cVSSScore />
	<relatedExploitRange />
	<attackComplexity />
	<levelofAuthenticationNeeded />
	<confidentialityImpact />
	<integrityImpact />
	<availabilityImpact />
	<collateralDamagePotential />
	<targetDistribution />
	<confidentialityRequirement />
	<integrityRequirement />
	<availabilityRequirement />
	<availabilityofExploit />
	<typeofFixAvailable />
	<levelofVerificationthatVulnerabilityExist />
	<cVSSEquation />
	</flaw>
</flaws>`
