(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(execute|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_value|select_values|select_rows|sql|lit|run|exec|async_exec|query|fetch)$")) @call
