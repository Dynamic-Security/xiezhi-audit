(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(get|of|newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString|copy|move|delete|deleteIfExists|newBufferedReader|newBufferedWriter|lines)$")) @call
