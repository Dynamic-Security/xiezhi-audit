(member_call_expression
  object: (variable_name) @object
  name: (name) @method
  (#eq? @object "$this")
  (#match? @method "^(authorize|authorizeResource|denyAccessUnlessGranted)$")) @call
(scoped_call_expression
  scope: (_) @object
  name: (name) @method
  (#match? @object "(^|\\\\)Gate$")
  (#match? @method "^(authorize|allows|denies|check|any|none)$")) @call
