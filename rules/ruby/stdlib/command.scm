(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(system|exec|spawn|syscall)$")) @call
