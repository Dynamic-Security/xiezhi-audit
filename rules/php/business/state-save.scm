(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(save|push|saveOrFail|persist)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(save|push|saveOrFail|persist)$")) @call
