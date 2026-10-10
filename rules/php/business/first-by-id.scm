(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(first|firstOrFail|sole|find|findOrEmpty|findOrFail)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(first|firstOrFail|sole|find|findOrEmpty|findOrFail)$")) @call
