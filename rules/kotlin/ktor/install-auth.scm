(call_expression
  (call_expression
    (identifier) @fn
    (value_arguments (value_argument (identifier) @plugin)))
  (#eq? @fn "install")
  (#match? @plugin "^(Authentication|Sessions)$")) @call
