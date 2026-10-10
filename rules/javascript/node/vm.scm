([(call_expression
    function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
    arguments: (arguments) @args)
  (new_expression
    constructor: (member_expression object: (_) @receiver property: (property_identifier) @method)
    arguments: (arguments) @args)] @call
 (#match? @method "^(runInNewContext|runInThisContext|runInContext|compileFunction|Script)$"))
