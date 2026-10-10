[(assignment left: (navigation_expression . (_) (identifier) @field .)
   (#match? @field "^(status|state|orderStatus|payStatus|auditStatus|approveStatus|approved|paid|role|roles|roleId|enabled|locked|deleted|owner|ownerId|userId|tenantId)$")) @call
 (call_expression
   (navigation_expression (_) (identifier) @method . (#eq? @method "copy"))
   (value_arguments (value_argument (identifier) @field (_)))
   (#match? @field "^(status|state|orderStatus|payStatus|auditStatus|approveStatus|approved|paid|role|roles|roleId|enabled|locked|deleted|owner|ownerId|userId|tenantId)$")) @call]
