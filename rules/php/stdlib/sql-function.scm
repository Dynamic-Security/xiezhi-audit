(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(mysql_query|mysqli_query|mysqli_multi_query|mysqli_real_query|mysql_unbuffered_query|pg_query|pg_send_query|sqlite_query|odbc_exec|db2_exec|oci_parse)$")) @call
