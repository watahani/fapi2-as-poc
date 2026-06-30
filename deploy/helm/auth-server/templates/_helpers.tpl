{{- define "auth-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "auth-server.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "auth-server.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "auth-server.labels" -}}
app.kubernetes.io/name: {{ include "auth-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "auth-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auth-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "auth-server.postgresHost" -}}
{{- if .Values.postgres.enabled -}}
{{- printf "%s-postgres" (include "auth-server.fullname" .) -}}
{{- else -}}
{{- .Values.database.host -}}
{{- end -}}
{{- end -}}
