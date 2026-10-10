(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list . (_) @template) @args
  (#match? @method "^process$")
  (#not-match? @template "^\"")) @call
