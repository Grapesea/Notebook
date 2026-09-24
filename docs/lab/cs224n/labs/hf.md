# Huggingface Transformer Tutorial

这个实验的架构是其中的前2项，不涉及 post training.

<center><img src="https://huggingface.co/datasets/huggingface-course/documentation-images/resolve/main/en/chapter2/full_nlp_pipeline-dark.svg" alt="calendar" style="zoom:67%;" /></center>

使用了一个 RoBERTa 情感分类模型，做 pretraining 的监督微调.

一些基本规则:

```python
from transformers import AutoModelForCausalLM

gpt2_tokenizer = AutoTokenizer.from_pretrained('gpt2')
```

找基座模型，如 gpt2 作为预训练的decoder.



