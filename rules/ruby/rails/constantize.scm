(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(constantize|safe_constantize)$")) @call
