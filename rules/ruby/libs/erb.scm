(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(new|parse)$")) @call
