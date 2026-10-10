(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(load|parse)$")) @call
