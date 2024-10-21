package main

import (
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestReadXML(t *testing.T) {
	var bytes []byte
	issues := readXML(bytes)
	assert.Equal(t, len(issues), 0)

	issues = readXML([]byte(exampleOutput))

	expectedIssues := make([]*v1.Issue, 8)
	classIssue := &v1.Issue{
		Target:      "com/h3xstream/findsecbugs/injection/BasicInjectionDetector.ClassLine.java:48-188",
		Type:        "PATH_TRAVERSAL_IN",
		Title:       "Potential Path Traversal (file read)",
		Severity:    v1.Severity_SEVERITY_MEDIUM,
		Cvss:        0.0,
		Confidence:  v1.Confidence_CONFIDENCE_MEDIUM,
		Description: "This API (java/io/File.<init>(Ljava/lang/String;)V) reads a file whose location might be specified by user input",
	}
	expectedIssues[0] = classIssue
	methodIssue := proto.Clone(classIssue).(*v1.Issue)
	methodIssue.Target = "com/h3xstream/findsecbugs/injection/BasicInjectionDetector.MethodLine.java:155-161"
	expectedIssues[1] = methodIssue

	sourceIssue0 := proto.Clone(methodIssue).(*v1.Issue)
	sourceIssue0.Target = "com/h3xstream/findsecbugs/injection/BasicInjectionDetector.SourceLine0.java:155-155"
	expectedIssues[2] = sourceIssue0

	sourceIssue1 := proto.Clone(sourceIssue0).(*v1.Issue)
	sourceIssue1.Target = "com/h3xstream/findsecbugs/FindSecBugsGlobalConfig.SourceLine1.java:53-53"
	expectedIssues[3] = sourceIssue1

	classIssue = &v1.Issue{
		Target:      "com/h3xstream/findsecbugs/injection/InjectionPoint.ClassLine.java:26-52",
		Type:        "EI_EXPOSE_REP",
		Title:       "May expose internal representation by returning reference to mutable object",
		Severity:    v1.Severity_SEVERITY_LOW,
		Cvss:        0.0,
		Confidence:  v1.Confidence_CONFIDENCE_MEDIUM,
		Description: "com.h3xstream.findsecbugs.injection.InjectionPoint.getInjectableArguments() may expose internal representation by returning InjectionPoint.injectableArguments",
	}
	expectedIssues[4] = classIssue

	methodIssue1 := proto.Clone(classIssue).(*v1.Issue)
	methodIssue1.Target = "com/h3xstream/findsecbugs/injection/InjectionPoint.MethodLine.java:39-39"
	expectedIssues[5] = methodIssue1

	fieldIssue := proto.Clone(classIssue).(*v1.Issue)
	fieldIssue.Target = "com/h3xstream/findsecbugs/injection/InjectionPoint.FieldLine.java:-"
	expectedIssues[6] = fieldIssue

	sourceIssue2 := proto.Clone(classIssue).(*v1.Issue)
	sourceIssue2.Target = "com/h3xstream/findsecbugs/injection/InjectionPoint.SourceLine1.java:39-40"
	expectedIssues[7] = sourceIssue2

	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Target == issue.Target {
				singleMatch++
				found++
				assert.Equal(t, singleMatch, 1)
				assert.EqualValues(t, expected.Type, issue.Type)
				assert.EqualValues(t, expected.Title, issue.Title)
				assert.EqualValues(t, expected.Severity, issue.Severity)
				assert.EqualValues(t, expected.Cvss, issue.Cvss)
				assert.EqualValues(t, expected.Confidence, issue.Confidence)
				assert.EqualValues(t, expected.Description, issue.Description)
			}
		}
	}
	assert.Equal(t, found, len(issues))
}

const exampleOutput = `
<?xml version="1.0" encoding="UTF-8"?>

<BugCollection version="3.1.12" sequence="0" timestamp="1586189624000" analysisTimestamp="1586189616607" release="">
  <Project projectName="">
    <Jar>/</Jar>
  </Project>
<BugInstance type="PATH_TRAVERSAL_IN" priority="2" rank="12" abbrev="SECPTI" category="SECURITY" instanceHash="ad9a7f908979ab4ffb356ccad009849e" instanceOccurrenceNum="0" instanceOccurrenceMax="0" cweid="22">
<ShortMessage>Potential Path Traversal (file read)</ShortMessage>
<LongMessage>This API (java/io/File.&lt;init&gt;(Ljava/lang/String;)V) reads a file whose location might be specified by user input</LongMessage>
<Class classname="com.h3xstream.findsecbugs.injection.BasicInjectionDetector" primary="true">
  <SourceLine classname="com.h3xstream.findsecbugs.injection.BasicInjectionDetector" start="48" end="188" sourcefile="BasicInjectionDetector.java"
  sourcepath="com/h3xstream/findsecbugs/injection/BasicInjectionDetector.ClassLine.java">
	<Message>At BasicInjectionDetector.java:[lines 48-188]</Message>
  </SourceLine>
  <Message>In class com.h3xstream.findsecbugs.injection.BasicInjectionDetector</Message>
</Class>
<Method classname="com.h3xstream.findsecbugs.injection.BasicInjectionDetector" name="loadCustomSinks" signature="(Ljava/lang/String;Ljava/lang/String;)V" isStatic="false" primary="true">
  <SourceLine classname="com.h3xstream.findsecbugs.injection.BasicInjectionDetector" start="155" end="161" startBytecode="0" endBytecode="460"
  sourcefile="BasicInjectionDetector.java" sourcepath="com/h3xstream/findsecbugs/injection/BasicInjectionDetector.MethodLine.java"/>
  <Message>In method com.h3xstream.findsecbugs.injection.BasicInjectionDetector.loadCustomSinks(String, String)</Message>
</Method>
<SourceLine classname="com.h3xstream.findsecbugs.injection.BasicInjectionDetector" primary="true" start="155" end="155" startBytecode="5" endBytecode="5"
sourcefile="BasicInjectionDetector.java" sourcepath="com/h3xstream/findsecbugs/injection/BasicInjectionDetector.SourceLine0.java">
  <Message>At BasicInjectionDetector.java:[line 155]</Message>
</SourceLine>
<String value="java/io/File.&lt;init&gt;(Ljava/lang/String;)V" role="Sink method">
  <Message>Sink method java/io/File.&lt;init&gt;(Ljava/lang/String;)V</Message>
</String>
<String value="0" role="Sink parameter">
  <Message>Sink parameter 0</Message>
</String>
<String value="com/h3xstream/findsecbugs/injection/BasicInjectionDetector.loadCustomSinks(Ljava/lang/String;Ljava/lang/String;)V parameter 1" role="Unknown source">
  <Message>Unknown source com/h3xstream/findsecbugs/injection/BasicInjectionDetector.loadCustomSinks(Ljava/lang/String;Ljava/lang/String;)V parameter 1</Message>
</String>
<SourceLine classname="com.h3xstream.findsecbugs.FindSecBugsGlobalConfig" start="53" end="53" startBytecode="1"
endBytecode="1" sourcefile="FindSecBugsGlobalConfig.java" sourcepath="com/h3xstream/findsecbugs/FindSecBugsGlobalConfig.SourceLine1.java">
  <Message>At FindSecBugsGlobalConfig.java:[line 53]</Message>
</SourceLine>
</BugInstance>
<BugInstance type="EI_EXPOSE_REP" priority="2" rank="18" abbrev="EI" category="MALICIOUS_CODE" instanceHash="ad7f9636b7e868a48901d62a558b8664" instanceOccurrenceNum="0" instanceOccurrenceMax="0" cweid="374">
<ShortMessage>May expose internal representation by returning reference to mutable object</ShortMessage>
<LongMessage>com.h3xstream.findsecbugs.injection.InjectionPoint.getInjectableArguments() may expose internal representation by returning InjectionPoint.injectableArguments</LongMessage>
<Class classname="com.h3xstream.findsecbugs.injection.InjectionPoint" primary="true">
  <SourceLine classname="com.h3xstream.findsecbugs.injection.InjectionPoint0" start="26" end="52" sourcefile="InjectionPoint.java"
  sourcepath="com/h3xstream/findsecbugs/injection/InjectionPoint.ClassLine.java">
	<Message>At InjectionPoint.java:[lines 26-52]</Message>
  </SourceLine>
  <Message>In class com.h3xstream.findsecbugs.injection.InjectionPoint</Message>
</Class>
<Method classname="com.h3xstream.findsecbugs.injection.InjectionPoint1" name="getInjectableArguments" signature="()[I" isStatic="false" primary="true">
  <SourceLine classname="com.h3xstream.findsecbugs.injection.InjectionPoint" start="39" end="39" startBytecode="0" endBytecode="46"
  sourcefile="InjectionPoint.java" sourcepath="com/h3xstream/findsecbugs/injection/InjectionPoint.MethodLine.java"/>
  <Message>In method com.h3xstream.findsecbugs.injection.InjectionPoint.getInjectableArguments()</Message>
</Method>
<Field classname="com.h3xstream.findsecbugs.injection.InjectionPoint" name="injectableArguments" signature="[I" isStatic="false" primary="true">
  <SourceLine classname="com.h3xstream.findsecbugs.injection.InjectionPoint" sourcefile="InjectionPoint.java"
  sourcepath="com/h3xstream/findsecbugs/injection/InjectionPoint.FieldLine.java">
	<Message>In InjectionPoint.java</Message>
  </SourceLine>
  <Message>Field com.h3xstream.findsecbugs.injection.InjectionPoint.injectableArguments</Message>
</Field>
<SourceLine classname="com.h3xstream.findsecbugs.injection.InjectionPoint3" primary="true" start="39" end="40" startBytecode="4"
 endBytecode="4" sourcefile="InjectionPoint.java" sourcepath="com/h3xstream/findsecbugs/injection/InjectionPoint.SourceLine1.java">
  <Message>At InjectionPoint.java:[line 39]</Message>
</SourceLine>
</BugInstance>
</BugCollection>`
