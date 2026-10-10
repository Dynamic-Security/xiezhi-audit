(decorated_definition
  (decorator
    (call
      function: (attribute object: (_) @router attribute: (identifier) @verb)
      arguments: (argument_list) @args) @call)
  definition: (function_definition) @handler
  (#match? @verb "^(get|post|put|delete|patch|head|options|api_route)$"))
