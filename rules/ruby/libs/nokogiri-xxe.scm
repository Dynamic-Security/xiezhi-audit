(call
  receiver: (_) @receiver
  method: (_) @method
  (#match? @method "^(XML|parse)$")) @call
