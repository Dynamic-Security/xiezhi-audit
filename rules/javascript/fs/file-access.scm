(call_expression
  function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
  arguments: (arguments) @args
  (#match? @method "^(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|open|openSync|readdir|readdirSync|copyFile|copyFileSync|rename|renameSync|access|stat|outputFile|readJson|readJSON|remove)$")) @call
