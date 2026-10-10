(object_creation_expression
  type: (_) @type
  arguments: (argument_list) @args
  (#match? @type "^(System\\.Data\\.SqlClient\\.|Microsoft\\.Data\\.SqlClient\\.)?(Sql|Sqlite|Npgsql|MySql|Oracle|OleDb|Odbc|Db2|Fb)Command$")) @call
