(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(file_get_contents|fopen|readfile|file|unlink|copy|rename|file_put_contents|opendir|scandir|rmdir|parse_ini_file|highlight_file|show_source|fpassthru|SplFileObject)$")
  (#not-match? @args "^\\(\\s*['\"](https?|ftp|php)://")) @call
