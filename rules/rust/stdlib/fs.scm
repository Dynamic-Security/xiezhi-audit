(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(read|read_to_string|read_to_end|write|remove_file|remove_dir|remove_dir_all|create_dir_all|copy|rename|read_dir|open|create|metadata|canonicalize|hard_link|symlink)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(read|read_to_string|read_to_end|write|remove_file|remove_dir|remove_dir_all|create_dir_all|copy|rename|read_dir|open|create|metadata|canonicalize|hard_link|symlink)$")) @call
(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(read|read_to_string|read_to_end|write|remove_file|remove_dir|remove_dir_all|create_dir_all|copy|rename|read_dir|open|create|metadata|canonicalize|hard_link|symlink)$")) @call
(call_expression
  function: (generic_function function: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(read|read_to_string|read_to_end|write|remove_file|remove_dir|remove_dir_all|create_dir_all|copy|rename|read_dir|open|create|metadata|canonicalize|hard_link|symlink)$")) @call
