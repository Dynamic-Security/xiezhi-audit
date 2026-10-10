[(binary_expression
   left: (string_literal) @literal
   (#match? @literal "^\"redirect:")) @call
 ((string_literal) @literal @call
   (#match? @literal "^\"redirect:"))]
