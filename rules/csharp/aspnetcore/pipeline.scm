(invocation_expression
  function: (member_access_expression
    expression: (_) @receiver
    name: [(identifier) @method (generic_name (identifier) @method)])
  arguments: (argument_list) @args
  (#match? @method "^(UseAuthentication|UseAuthorization|UseMiddleware|UseCors|UseAntiforgery|AddAuthentication|AddAuthorization|AddAuthorizationBuilder|AddJwtBearer|AddCookie|AddPolicy|AddFallbackPolicy|SetFallbackPolicy|AddIdentity|AddDefaultIdentity|RequireAuthorization)$")) @call
