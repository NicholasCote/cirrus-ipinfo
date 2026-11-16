{{- define "ipinfo.fullname" -}}{{ .Release.Name | trunc 40 | trimSuffix "-" }}{{- end -}}

{{- define "ipinfo.labels" -}}
app.kubernetes.io/name: cirrus-ipinfo
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "ipinfo.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end -}}

{{- define "ipinfo.dbUriSecret" -}}
{{- if .Values.postgres.enabled -}}{{ include "ipinfo.fullname" . }}-db-app{{- else -}}{{ required "postgres.existingUriSecret is required when postgres.enabled=false" .Values.postgres.existingUriSecret }}{{- end -}}
{{- end -}}

{{/* Environment shared by every pipeline container. */}}
{{- define "ipinfo.env" -}}
envFrom:
  - secretRef:
      name: {{ include "ipinfo.fullname" . }}
  - configMapRef:
      name: {{ include "ipinfo.fullname" . }}
env:
  - name: IPINFO_DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: {{ include "ipinfo.dbUriSecret" . }}
        key: uri
{{- end -}}

{{- define "ipinfo.excludeCidrs" -}}
{{- $parts := list -}}
{{- range $cluster, $cidrs := .Values.excludeCidrs -}}
{{- if $cidrs }}{{- $parts = append $parts (printf "%s=%s" $cluster (join "," $cidrs)) -}}{{- end -}}
{{- end -}}
{{- join ";" $parts -}}
{{- end -}}
