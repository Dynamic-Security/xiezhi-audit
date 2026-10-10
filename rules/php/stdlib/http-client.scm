(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(get|post|put|patch|delete|head|request|send|requestAsync|getAsync|postAsync|sendAsync)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(get|post|put|patch|delete|head|request|send|requestAsync|getAsync|postAsync|sendAsync)$")) @call
(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(get|post|put|patch|delete|head|send)$")) @call
