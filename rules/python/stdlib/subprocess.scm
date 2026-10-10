(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(run|call|check_call|check_output|Popen)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(run|call|check_call|check_output|Popen)$")) @call
