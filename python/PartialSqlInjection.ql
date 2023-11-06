/**
 * @kind path-problem
 * @description Partial Query: https://aegilops.github.io/posts/partial-flow-in-codeql-with-configsig/
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery

int explorationLimit() { result = 20 }  // [1]
module FlowsPartial = SqlInjectionFlow::FlowExploration<explorationLimit/0>;   // [2]

import FlowsPartial::PartialPathGraph  // [3]
from FlowsPartial::PartialPathNode source, FlowsPartial::PartialPathNode sink  // [4]
where FlowsPartial::partialFlow(source, sink, _)  // [5]
select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
  "this source"
