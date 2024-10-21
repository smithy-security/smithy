{{/*
Expand the name of the chart.
*/}}
{{- define "deduplication_db_migrations.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "deduplication_db_migrations.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "deduplication_db_migrations.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deduplication_db_migrations.labels" -}}
helm.sh/chart: {{ include "deduplication_db_migrations.chart" . }}
{{ include "deduplication_db_migrations.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deduplication_db_migrations.selectorLabels" -}}
app.kubernetes.io/name: {{ include "deduplication_db_migrations.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "deduplication_db_migrations.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "deduplication_db_migrations.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Create the name of the service account to use
*/}}

{{- define "deduplication_db_migrations.imageName" -}}
{{- if .Values.image.repository }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion )}}
{{- else }}
{{- printf "%s/%s:%s" (.Values.image.registry | default "ghcr.io/smithy-security/smithy") "smithyctl" (.Values.image.tag | default .Chart.AppVersion )}}
{{- end }}
{{- end }}
