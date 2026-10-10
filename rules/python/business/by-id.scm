(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(get|filter|filter_by|get_or_404|get_or_none|first_or_404)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(get_object_or_404|get_list_or_404)$")) @call
