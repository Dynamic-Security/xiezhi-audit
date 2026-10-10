(call_expression
  function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|ReadDir|Mkdir|MkdirAll|Rename)$")) @call
