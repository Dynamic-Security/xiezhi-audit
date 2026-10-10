(assignment_expression
  left: (member_access_expression expression: (_) @receiver name: (identifier) @method)
  right: (_) @args
  (#match? @method "^(Status|State|OrderStatus|PaymentStatus|PayStatus|ApprovalStatus|IsPaid|IsApproved|Approved|Role|Roles|RoleId|IsAdmin|IsEnabled|IsLocked|IsDeleted|OwnerId|UserId|TenantId|EmployeeId)$")) @call
