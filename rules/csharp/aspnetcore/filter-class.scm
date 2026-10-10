(class_declaration
  (base_list [(identifier) @super (generic_name (identifier) @super) (qualified_name name: (identifier) @super)])
  (#match? @super "^(IMiddleware|IAuthorizationFilter|IAsyncAuthorizationFilter|IActionFilter|IAsyncActionFilter|ActionFilterAttribute|AuthorizeAttribute|AuthorizationHandler|IAuthorizationHandler|AuthenticationHandler|IEndpointFilter)$")) @class
