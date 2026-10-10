(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|open|openSync|readdir|readdirSync|copyFile|copyFileSync|rename|renameSync|access|stat|outputFile|readJson|readJSON|remove)$")) @call
