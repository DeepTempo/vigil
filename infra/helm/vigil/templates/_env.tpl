{{/*
Shared `env:` and `envFrom:` block for backend/daemon/llm-worker pods.

Usage (inside a container spec):
  envFrom:
    {{- include "vigil.envFrom" . | nindent 12 }}
  env:
    {{- include "vigil.env" . | nindent 12 }}

Both helpers take the root context directly. They pull the generated ConfigMap
and Secret, plus the discrete POSTGRES_* connection parts and REDIS_URL (which
have to be assembled at render time because they embed service DNS + a secret
reference). The app builds and URL-encodes the DSN from POSTGRES_* itself, so
passwords with special characters survive intact (no pre-built DATABASE_URL).

NOTE: secret.yaml is only rendered when secrets.existingSecret is empty AND
secrets.externalSecret.enabled is false. Either way the secretRef below points
at a Secret of the same name (user-supplied, ESO-materialized, or
chart-templated).
*/}}
{{- define "vigil.envFrom" -}}
- configMapRef:
    name: {{ include "vigil.configmap.fullname" . }}
- secretRef:
    name: {{ include "vigil.secret.fullname" . }}
{{- end -}}

{{- define "vigil.env" -}}
- name: POSTGRES_HOST
  value: {{ include "vigil.postgres.host" . | quote }}
- name: POSTGRES_PORT
  value: {{ include "vigil.postgres.port" . | toString | quote }}
- name: POSTGRES_DB
  value: {{ include "vigil.postgres.database" . | quote }}
- name: POSTGRES_USER
  value: {{ include "vigil.postgres.username" . | quote }}
{{- if .Values.redis.bitnami.enabled }}
{{- if .Values.redis.bitnami.auth.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "vigil.redis.bitnami.passwordSecret" . }}
      key: {{ include "vigil.redis.bitnami.passwordSecretKey" . }}
{{- end }}
- name: REDIS_URL
  value: {{ include "vigil.redis.url" . | quote }}
{{- else if .Values.redis.enabled }}
- name: REDIS_URL
  value: {{ include "vigil.redis.url" . | quote }}
{{- else if .Values.redis.external.url }}
- name: REDIS_URL
  value: {{ .Values.redis.external.url | quote }}
{{- else if .Values.redis.external.existingSecret }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.external.existingSecret }}
      key: {{ .Values.redis.external.existingSecretKey | default "REDIS_URL" }}
{{- end }}
{{- end -}}

{{/*
Discrete Redis parts, added on top of vigil.env for the agent pods only.

The same reasoning that keeps POSTGRES_* discrete rather than a DSN. Under
Bitnami auth vigil.redis.url renders `redis://:$(REDIS_PASSWORD)@host:6379/0`,
and the kubelet substitutes that variable verbatim — no URL-encoding. A password
holding @ / : or # therefore produces a REDIS_URL that the agent's `new URL()`
misparses or rejects, and it is the queue connection, so the worker never drains.

Python is unaffected and keeps reading REDIS_URL; only the agent prefers these,
and only when REDIS_HOST is set (services/agent/core/db.ts::redisConfig).

Nothing is emitted for an external Redis supplied as a URL: there are no parts to
name, so the agent falls back to REDIS_URL — which it now percent-decodes, so a
correctly-escaped DSN works.
*/}}
{{- define "vigil.agentRedisEnv" -}}
{{- if .Values.redis.bitnami.enabled }}
- name: REDIS_HOST
  value: {{ .Values.redis.bitnami.fullnameOverride | default (printf "%s-redis-master" .Release.Name) | quote }}
- name: REDIS_PORT
  value: "6379"
- name: REDIS_DB
  value: {{ include "vigil.redis.database" . | quote }}
{{- else if .Values.redis.enabled }}
- name: REDIS_HOST
  value: {{ include "vigil.redis.fullname" . | quote }}
- name: REDIS_PORT
  value: {{ .Values.redis.service.port | default 6379 | toString | quote }}
- name: REDIS_DB
  value: {{ include "vigil.redis.database" . | quote }}
{{- end }}
{{- end -}}
