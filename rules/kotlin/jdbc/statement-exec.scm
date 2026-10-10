(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(execute|executeQuery|executeUpdate|executeLargeUpdate|addBatch)$")) @call
