(object_creation_expression
  type: (_) @type
  arguments: (argument_list) @args
  (#match? @type "^(System\\.IO\\.)?(FileStream|FileInfo|DirectoryInfo|StreamWriter)$")) @call
