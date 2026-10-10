(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(simplexml_load_string|simplexml_load_file)$")
  (#match? @args "LIBXML_NOENT|LIBXML_DTDLOAD")) @call
(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(loadXML|load|loadHTML|xml)$")
  (#match? @args "LIBXML_NOENT|LIBXML_DTDLOAD")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(loadXML|load|loadHTML|xml)$")
  (#match? @args "LIBXML_NOENT|LIBXML_DTDLOAD")) @call
