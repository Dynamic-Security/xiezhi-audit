(call_expression
  function: (member_expression
    object: (member_expression property: (property_identifier) @auth)
    property: (property_identifier) @method)
  (#eq? @auth "auth")
  (#eq? @method "default")) @call
