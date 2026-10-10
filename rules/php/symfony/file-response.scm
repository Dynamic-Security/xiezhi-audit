(object_creation_expression
  [(name) (qualified_name)] @method
  (arguments) @args
  (#match? @method "(^|\\\\)(BinaryFileResponse)$")) @call
(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(file)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(file)$")) @call
