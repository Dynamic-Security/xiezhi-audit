(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(getValue|setValue|parseExpression|findValue|findString|compile|callMethod|translateVariables)$")) @call
