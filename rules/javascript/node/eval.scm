([(call_expression function: (identifier) @method arguments: (arguments) @args)
  (new_expression constructor: (identifier) @method arguments: (arguments) @args)] @call
 (#match? @method "^(eval|Function)$"))
