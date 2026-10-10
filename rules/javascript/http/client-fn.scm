(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(axios|got|fetch|request|needle|superagent|phin|bent)$")) @call
