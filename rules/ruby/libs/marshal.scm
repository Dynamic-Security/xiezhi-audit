(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(load|restore)$")) @call
