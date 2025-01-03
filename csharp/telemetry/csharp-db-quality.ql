// /**
//  * @name Low CSharp analysis quality
//  * @description Low Csharp analysis quality
//  * @kind diagnostic
//  * @id csharp/diagnostic/database-quality
//  */

import csharp

signature module StatsSig {
    int getNumberOfOk();
  
    int getNumberOfNotOk();
  
    string getOkText();
  
    string getNotOkText();
  }
  
  module CallTargetStats implements StatsSig {
    int getNumberOfOk() { result = count(Call c | exists(c.getTarget())) }

    int getNumberOfNotOk() {
      result =
        count(Call c |
          not exists(c.getTarget()) and
          not c instanceof DelegateCall and
          not c instanceof DynamicExpr
        )
    }

  
    string getOkText() { result = "OK - >95% calls with call target" }
  
    string getNotOkText() { result = "LOW - <95% calls with call target (missing)" }
  }
  
  private class SourceExpr extends Expr {
    SourceExpr() { this.getFile().fromSource() }
  }
  
  private predicate hasGoodType(Expr e) {
    exists(e.getType()) and not e.getType() instanceof UnknownType
  }
  
  module ExprTypeStats implements StatsSig {
    int getNumberOfOk() { result = count(SourceExpr e | hasGoodType(e)) }
  
    int getNumberOfNotOk() { result = count(SourceExpr e | not hasGoodType(e)) }
    string getOkText() { result = "OK - >95% expressions with known type" }
  
    string getNotOkText() { result = "LOW - <95%  expressions with known type (unknown)" }
  }


//// Simple query
// select 
//   CallTargetStats::getNumberOfOk() * 100.0 / (CallTargetStats::getNumberOfOk() + CallTargetStats::getNumberOfNotOk()) as callTargetPercent,
//   ExprTypeStats::getNumberOfOk() * 100.0 / (ExprTypeStats::getNumberOfOk() + ExprTypeStats::getNumberOfNotOk()) as exprTypePercent

// Percent and text result for each stat
from float callTargetPercent, string callTargetResultText, float exprTypePercent, string exprTypeResultText
where
  exists(int ok, int notOk |
    ok = CallTargetStats::getNumberOfOk() and
    notOk = CallTargetStats::getNumberOfNotOk() and
    callTargetPercent = ok * 100.0 / (ok + notOk)
  ) and
  (
    callTargetPercent > 95.0 and callTargetResultText = CallTargetStats::getOkText() or
    callTargetPercent <= 95.0 and callTargetResultText = CallTargetStats::getNotOkText()
  ) and
  exists(int ok, int notOk |
    ok = ExprTypeStats::getNumberOfOk() and
    notOk = ExprTypeStats::getNumberOfNotOk() and
    exprTypePercent = ok * 100.0 / (ok + notOk)
  ) and
  (
    exprTypePercent > 95.0 and exprTypeResultText = ExprTypeStats::getOkText() or
    exprTypePercent <= 95.0 and exprTypeResultText = ExprTypeStats::getNotOkText()
  )
  // For MRVA only show results that are not OK
  and ( callTargetPercent < 95.0 or exprTypePercent < 95.0 )
select callTargetPercent, callTargetResultText, exprTypePercent, exprTypeResultText
