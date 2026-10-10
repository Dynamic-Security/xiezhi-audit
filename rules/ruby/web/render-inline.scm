(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(render|render_to_string)$")) @call
