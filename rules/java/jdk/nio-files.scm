(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(get|of|newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString|copy|move|delete|deleteIfExists|newBufferedReader|newBufferedWriter|lines)$")) @call
