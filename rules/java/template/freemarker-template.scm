(object_creation_expression
  type: [(type_identifier) @type (scoped_type_identifier (type_identifier) @type)]
  arguments: (argument_list) @args
  (#match? @type "^Template$")) @call
