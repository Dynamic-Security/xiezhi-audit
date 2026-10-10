(assignment_expression
  left: (member_access_expression expression: (_) @receiver name: (identifier) @method)
  right: (_) @args
  (#match? @method "^(Amount|Price|UnitPrice|Balance|Total|TotalAmount|TotalPrice|PayAmount|Quantity|Stock|Discount|Points|Credit|Salary|BaseSalary|GrossPay|NetPay|Bonus|Deduction)$")) @call
