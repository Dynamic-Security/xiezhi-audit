(call_expression
  function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(Query|QueryRow|QueryFunc|Exec|QueryContext|QueryRowContext|ExecContext|Prepare|PrepareContext|Raw|Select|Get|NamedExec|NamedQuery|Queryx|QueryRowx|MustExec)$")) @call
