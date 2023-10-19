/**
 * @name ANY cross-window communication with unrestricted target origin
 * @description Based on js/cross-window-information-leak.  
 *              When sending sensitive information to another window using `postMessage`,
 *              the origin of the target window should be restricted to avoid unintentional
 *              information leaks. 
 *              Looking for this pattern:  window.parent.postMessage('reloadPage', '*');
 * @kind problem
 * @problem.severity error
 * @security-severity 1.0
 * @precision low
 * @id js/cross-window-information-leak-any
 * @tags security
 *       external/cwe/cwe-201
 *       external/cwe/cwe-359
 */

import javascript

from MethodCallExpr mce
where mce.getArgument(1).getStringValue() = "*"
and mce.getMethodName() = "postMessage" 
select mce, "Unrestricted `postMessage` target origin: " + mce.getArgument(1)
