/**
 * Provides a taint-tracking configuration for reasoning about reflected
 * cross-site scripting vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `ReflectedXss::Configuration` is needed, otherwise
 * `ReflectedXssCustomizations` should be imported instead.
 */

//import go
//C:\repos\felickz\vscode-codeql-starter\ql\go\ql\lib\semmle\go\security\ReflectedXssCustomizations.qll
import ReflectedXssCustomizations

/**
 * Provides a taint-tracking configuration for reasoning about reflected
 * cross-site scripting vulnerabilities.
 */
module ReflectedXss {
  import CWE079.ReflectedXssCustomizations::ReflectedXss

  /**
   * DEPRECATED: Use `Flow` instead.
   *
   * A taint-tracking configuration for reasoning about XSS.
   */
  deprecated class Configuration extends TaintTracking::Configuration {
    Configuration() { this = "ReflectedXss" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    override predicate isSanitizer(DataFlow::Node node) {
      super.isSanitizer(node) or
      node instanceof Sanitizer
    }
  }

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

    predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
      node = any(DataFlow::MethodCallNode cn | cn.getTarget().hasQualifiedName("text/template", "Template", "ExecuteTemplate")).getArgument(2)
      and
      c = any(DataFlow::ContentSet c2)
    }

  }

  /** Tracks taint flow from untrusted data to XSS attack vectors. */
  module Flow = TaintTracking::Global<Config>;
}
