(function_declaration
  (modifiers
    (annotation [(user_type (identifier) @ann) (constructor_invocation (user_type (identifier) @ann))]) @annotation)
  (#match? @ann "^(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)$")) @method
