[(call_expression
   (call_expression (identifier) @verb (value_arguments) @args)
   (annotated_lambda)
   (#match? @verb "^(get|post|put|delete|patch|head|options)$")) @call
 (call_expression
   (identifier) @verb
   (annotated_lambda)
   (#match? @verb "^(get|post|put|delete|patch|head|options)$")) @call]
