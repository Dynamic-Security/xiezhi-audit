(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^const_get$")) @call
(call
  !receiver
  method: (identifier) @method
  (#match? @method "^const_get$")) @call
