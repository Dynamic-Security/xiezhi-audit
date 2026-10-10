(method_declaration
  (modifiers
    [(annotation name: (identifier) @ann) @annotation
     (marker_annotation name: (identifier) @ann) @annotation])
  name: (identifier) @name
  (#match? @ann "^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")) @method
