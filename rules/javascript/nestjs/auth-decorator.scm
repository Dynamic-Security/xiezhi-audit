([(decorator (call_expression function: (identifier) @name))
  (decorator (identifier) @name)] @decorator
 (#match? @name "^(UseGuards|Roles|Public|SkipAuth|AllowAnonymous|Permissions|RequirePermissions|RequireRoles|Auth|Authorized|Authenticated|Scopes|SetMetadata)$"))
