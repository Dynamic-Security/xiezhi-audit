(call_expression
  function: (field_expression value: (_) @receiver field: (field_identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(execute|query|query_one|query_opt|query_row|query_map|prepare|prepare_cached|batch_execute|simple_query|exec|exec_drop|exec_first|query_drop|query_first|query_iter|execute_unprepared|execute_batch|query_all|query_scalar)$")) @call
