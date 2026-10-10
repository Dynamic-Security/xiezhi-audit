(scoped_call_expression
  scope: (_) @router
  name: (name) @verb
  arguments: (arguments) @args
  (#match? @verb "^(get|post|put|patch|delete|any|rule|resource)$")) @call
(member_call_expression
  object: (_) @router
  name: (name) @verb
  arguments: (arguments) @args
  (#match? @verb "^(get|post|put|patch|delete|any|rule|resource)$")) @call
