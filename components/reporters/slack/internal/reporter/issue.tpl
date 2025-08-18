Smithy detected a vulnerability in *[{{ .TargetName }}]({{ .TargetLink }})*.

{{ if ne .Title "" }}*{{ .Title }}:*{{ end }}
{{ if ne .Description "" }}{{ .Description }}.{{ end }}

{{ if .IsRepository }}
*Location:* *{{ .FindingPath }}* between line {{ .FindingStartLine }} and {{ .FindingEndLine }} on branch *{{ .Reference }}*.
{{ else if .IsPurl }}
*Location:* *{{ .FindingPath }}*.
{{ end }}

*Finding info:*
- *ID:* [{{ .FindingID }}]({{ .FindingLink }})
- *Confidence:* {{ .Confidence }}
- *CWE:* [{{ .CWE }}]({{ .CWELink }})
- *CVE:* {{ .CVE }}
- *Reporting Tool:* {{ .Tool }}
- *Detected by Run:* [{{ .RunName }}]({{ .RunLink }})
