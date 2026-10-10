(decorated_definition
  (decorator (attribute object: (identifier) @router attribute: (identifier) @hook))
  definition: (function_definition) @def
  (#match? @hook "^(before_request|before_app_request)$"))
