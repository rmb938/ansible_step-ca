{
  {% raw %}
  "subject": {
    "commonName": {{ toJson .Subject.CommonName }},
    "country": "US",
    "organization": "Home Lab",
    "organizationalUnit": "HAProxy",
    "province": "Minnesota"
  },
  "sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
  "keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
  "keyUsage": ["digitalSignature"],
{{- end }}
  "extKeyUsage": ["serverAuth", "clientAuth"]
  {% endraw %}
}