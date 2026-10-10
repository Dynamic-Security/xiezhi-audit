(call
  !receiver
  method: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(erb|erubi|haml|slim|liquid|builder|markaby|rabl)$")) @call
