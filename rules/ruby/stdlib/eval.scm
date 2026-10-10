(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(eval|instance_eval|class_eval|module_eval)$")) @call
(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(eval|instance_eval|class_eval|module_eval)$")) @call
