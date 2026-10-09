# 词汇表

## Fields







## Exp Res

实验指标：

* TP: True Positive, 正确且召回
* FP: False Positive, 错误但召回
* FN: False Negative, 错误未召回
* TN: True Negative, 正确未召回

衍生指标：

* precision: $ = \dfrac{TP}{TP+FP}$
* recall: $= \dfrac{TP}{TP+FN}$
* accuracy: $= \dfrac{TP+TN}{TP+FN+TN+FP}$

* EM: exact match, 衡量预测值与答案是否一致

* F1: $= \dfrac{2 \times \text{precision} \times \text{recall}}{\text{precision} + \text{recall}}$