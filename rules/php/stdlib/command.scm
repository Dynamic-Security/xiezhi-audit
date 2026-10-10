(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|expect_popen)$")) @call
