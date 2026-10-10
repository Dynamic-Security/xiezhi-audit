(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(send|public_send|__send__|try|try!)$")) @call
(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(send|public_send|__send__)$")) @call
