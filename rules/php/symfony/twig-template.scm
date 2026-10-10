(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(createTemplate)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(createTemplate)$")) @call
