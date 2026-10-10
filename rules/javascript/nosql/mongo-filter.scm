(call_expression
  function: [(member_expression object: (_) @receiver property: (property_identifier) @method)
             ; TS parses `await x.m<T>(…)` as a call of an await expression
             (await_expression (member_expression object: (_) @receiver property: (property_identifier) @method))]
  arguments: (arguments) @args
  (#match? @method "^(find|findOne|where|updateOne|updateMany|deleteOne|deleteMany|findOneAndUpdate|findOneAndDelete|countDocuments|count|aggregate|replaceOne)$")) @call
