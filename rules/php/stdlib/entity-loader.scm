(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(libxml_disable_entity_loader)$")
  (#match? @args "([Ff]alse|FALSE)")) @call
