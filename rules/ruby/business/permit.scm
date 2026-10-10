(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(permit|permit!)$")) @call
