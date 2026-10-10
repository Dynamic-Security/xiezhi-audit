(call_expression
  (identifier) @type
  (value_arguments) @args
  (#match? @type "^(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)$")) @call
