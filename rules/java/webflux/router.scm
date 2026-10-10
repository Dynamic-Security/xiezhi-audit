(method_invocation
  name: (identifier) @verb
  arguments: (argument_list . (string_literal))
  (#match? @verb "^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")) @call
