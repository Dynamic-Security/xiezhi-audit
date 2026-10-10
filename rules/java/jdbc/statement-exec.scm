(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(execute|executeQuery|executeUpdate|executeLargeUpdate|addBatch)$")) @call
