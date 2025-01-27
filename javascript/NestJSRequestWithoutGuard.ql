/**
 * @name NestJS Controller without UseGuards
 * @description Finds NestJS controllers that do not have a UseGuards decorator.
 * @kind problem
 * @problem.severity warning
 * @id js/nestjs-controller-without-useguards
 * @tags security
 *       correctness
 *       external/cwe/cwe-284
 *       external/cwe/cwe-285
 *       external/cwe/cwe-862
 * @precision high
 *       
 */

// Potential Enhancements
// - Allow for Controllers without guard if all endpoints have a guard applied (also loop through MethodDefinitions not just ClassDefinitions)
// - Allow for a list of known endpoints where guards that are not required (consider using data extensions)
// - Detect use of global scoped guards `app.useGlobalGuards` (dependency injection cases)
// - Detect guards that do not apply authorization (heurestics by name or by allowlist in data extensions for strict enforcement)
// - IF wish to turn this into a security severity (critical/high/medium/low) - add @security-severity tag followed by the #.# CVSS score

import javascript

// Find all NestJS `@Controller`'s that do not have a `@UseGuards` decorator
from ClassDefinition controller, Decorator controllerDecorator, VarRef controllerVarRef
where
    controllerDecorator = controller.getADecorator() and
    controllerVarRef.getParentExpr() = controllerDecorator.getExpression() and
    controllerVarRef.getName() = "Controller" and
    not exists(Decorator guardDecorator, VarRef guardVarRef |
        guardDecorator = controller.getADecorator() and
        guardVarRef.getParentExpr() = guardDecorator.getExpression() and
        guardVarRef.getName() = "UseGuards"
    )
select controllerVarRef, "This $@ does not have a @UseGuards decorator.", controller, "endpoint"//, controllerVarRef.getType(), "type" 
