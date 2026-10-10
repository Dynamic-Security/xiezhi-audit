(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(redirect_to|redirect|redirect_back_or_to)$")) @call
