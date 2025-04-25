Smithy detected a vulnerability in [{{ .TargetName }}|{{ .TargetLink }}].

{{ if .IsRepository }}
Location: *{{ .FindingPath }}* between line {{ .FindingStartLine }} and {{ .FindingEndLine }} on branch *{{ .Reference }}*.
{{ else if .IsPurl }}
Location: *{{ .FindingPath }}*.
{{ end }}

||ID||Confidence||CWE||CVE||Reporting Tool||Detected by Run||
|[{{ .FindingID }}|{{ .FindingLink }}]|{{ .Confidence }}|[{{ .CWE }}|{{ .CWELink }}]|{{ .CVE }}|{{ .Tool }}|[{{ .RunName }}|{{ .RunLink }}]|
