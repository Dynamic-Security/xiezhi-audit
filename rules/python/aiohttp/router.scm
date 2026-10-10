(call
  function: (attribute attribute: (identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(add_get|add_post|add_put|add_patch|add_delete|add_head|add_route|add_view|get|post|put|patch|delete|head|route|view)$")) @call
