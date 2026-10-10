(decorated_definition
  (decorator
    (call
      function: (attribute object: (_) @router attribute: (identifier) @verb)
      arguments: (argument_list) @args) @call)
  definition: [(function_definition) (class_definition)] @handler
  (#match? @verb "^(get|post|put|patch|delete|head|route|view)$"))
