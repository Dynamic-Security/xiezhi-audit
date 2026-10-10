(attribute
  name: (identifier) @ann
  (#match? @ann "^(Authorize|AllowAnonymous|TypeFilter|ServiceFilter|ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|IgnoreAntiforgeryToken|RequireHttps|[A-Za-z]*(Auth|Permission|Role|Jwt|ApiKey|Guard|Acl|Rbac|Secur|Login|Claim)[A-Za-z]*)(Attribute)?$")) @attribute
