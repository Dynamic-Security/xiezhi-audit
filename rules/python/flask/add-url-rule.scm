(call
  function: (attribute object: (_) @router attribute: (identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(add_url_rule|add_resource)$")) @call
