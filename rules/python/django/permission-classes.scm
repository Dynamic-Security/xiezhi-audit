(class_definition
  body: (block
    (expression_statement
      (assignment left: (identifier) @name right: (_) @value)))
  (#match? @name "^(permission_classes|authentication_classes)$")) @class
