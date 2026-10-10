(member_call_expression
  name: (name) @verb
  arguments: (arguments)
  (#match? @verb "^(get|post|put|patch|delete|options|any|map)$")) @call
