(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^html_safe$")) @call
(call
  !receiver
  method: (identifier) @method
  (#match? @method "^raw$")) @call
