(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork|execa|execaCommand|execaSync)$")) @call
