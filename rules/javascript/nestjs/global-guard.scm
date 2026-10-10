(call_expression
  function: (member_expression property: (property_identifier) @method)
  (#match? @method "^(useGlobalGuards|forRoutes)$")) @call
