(assignment
  left: (attribute object: (_) @receiver attribute: (identifier) @field)
  right: (_) @value
  (#match? @field "^(status|state|role|roles|is_admin|is_staff|is_superuser|balance|amount|price|total|paid|paid_at|credit|credits|quantity|discount|approved|verified|owner|owner_id|user_id)$")) @call
(augmented_assignment
  left: (attribute object: (_) @receiver attribute: (identifier) @field)
  right: (_) @value
  (#match? @field "^(balance|amount|price|total|credit|credits|quantity|discount)$")) @call
(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @method "update")) @call
