{{/* Expand the name of the chart. */}}
{{- define "scrub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "scrub.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "scrub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "scrub.labels" -}}
helm.sh/chart: {{ include "scrub.chart" . }}
{{ include "scrub.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "scrub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scrub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "scrub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "scrub.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "scrub.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the ConfigMap holding scrub.yaml. */}}
{{- define "scrub.configMapName" -}}
{{- default (printf "%s-config" (include "scrub.fullname" .)) .Values.existingConfigMap -}}
{{- end -}}

{{/* Name of the Secret holding the at-rest encryption key. */}}
{{- define "scrub.secretName" -}}
{{- default (printf "%s-env" (include "scrub.fullname" .)) .Values.sessions.existingSecret -}}
{{- end -}}

{{/* True when we should wire the at-rest encryption key from a Secret. */}}
{{- define "scrub.hasEncryptionKey" -}}
{{- if or .Values.sessions.encryptionKey .Values.sessions.existingSecret -}}true{{- end -}}
{{- end -}}
