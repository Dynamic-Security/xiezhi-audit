(call_expression
  function: (field_expression value: (_) @receiver field: (field_identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(eval|eval_expression|eval_with_scope|run|run_with_scope|load|execute_script)$")) @call
