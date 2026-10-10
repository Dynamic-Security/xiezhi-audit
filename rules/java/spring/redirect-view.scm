(binary_expression
  left: (string_literal) @literal
  right: (_) @args
  (#match? @literal "^\"redirect:")) @call
