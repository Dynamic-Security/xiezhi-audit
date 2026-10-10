(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(find|findOrFail|findOrNew|findMany|findOneBy)$")) @call
(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(find|findOrFail|findOrNew|findOneBy|findOneById|findById|getById|loadById)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(find|findOrFail|findOrNew|findOneBy|findOneById|findById|getById|loadById)$")) @call
