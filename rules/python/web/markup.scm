(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(Markup|mark_safe)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(Markup|mark_safe)$")) @call
