(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(update_option|update_site_option|update_user_meta|update_usermeta|wp_update_user|add_option|delete_option)$")) @call
