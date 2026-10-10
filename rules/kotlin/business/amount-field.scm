[(assignment left: (navigation_expression . (_) (identifier) @field .)
   (#match? @field "^(amount|price|balance|total|totalAmount|totalPrice|payAmount|quantity|count|stock|discount|points|credit|score|limit|creditLimit|principal|rate|interestRate)$")) @call
 (call_expression
   (navigation_expression (_) (identifier) @method . (#eq? @method "copy"))
   (value_arguments (value_argument (identifier) @field (_)))
   (#match? @field "^(amount|price|balance|total|totalAmount|totalPrice|payAmount|quantity|count|stock|discount|points|credit|score|limit|creditLimit|principal|rate|interestRate)$")) @call]
