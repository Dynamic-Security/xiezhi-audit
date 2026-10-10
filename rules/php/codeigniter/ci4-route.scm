(member_call_expression
  object: (variable_name) @recv
  name: (name) @verb
  arguments: (arguments)
  (#eq? @recv "$routes")
  (#match? @verb "^(get|post|put|patch|delete|options|head|add|match|resource)$")) @call
