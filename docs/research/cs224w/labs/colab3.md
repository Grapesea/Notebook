# Colab 3

> [!IMPORTANT] 
>
> 本实验目的是实现 GraphSAGE 的基础函数.

## Setup

```py
# Install torch geometric
import os
import torch
import torch_geometric

if 'IS_GRADESCOPE_ENV' not in os.environ:
	!pip install torch==2.11.0 # 一开始是2.4.0，改成2.11.0了
if 'IS_GRADESCOPE_ENV' not in os.environ:
	torch_version = str(torch.__version__)
	scatter_src = f"https://pytorch-geometric.com/whl/torch-{torch_version}.html"
	sparse_src = f"https://pytorch-geometric.com/whl/torch-{torch_version}.html"
	!pip install torch-scatter -f $scatter_src
  	!pip install torch-sparse -f $sparse_src
  	!pip install torch-geometric
  	!pip install -q git+https://github.com/snap-stanford/deepsnap.git
```

GNN Stack Module：

```python
import torch
import torch_scatter
import torch.nn as nn
import torch.nn.functional as F
import torch_geometric.nn as pyg_nn
import torch_geometric.utils as pyg_utils

from torch import Tensor
from typing import Union, Tuple, Optional
from torch_geometric.typing import (OptPairTensor, Adj, Size, NoneType,
                                    OptTensor)

from torch.nn import Parameter, Linear
from torch_sparse import SparseTensor, set_diag
from torch_geometric.nn.conv import MessagePassing
from torch_geometric.utils import remove_self_loops, add_self_loops, softmax

class GNNStack(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, args, emb=False):
        super(GNNStack, self).__init__()
        conv_model = self.build_conv_model(args.model_type)
        self.convs = nn.ModuleList()
        self.convs.append(conv_model(input_dim, hidden_dim))
        assert (args.num_layers >= 1), 'Number of layers is not >=1'
        for l in range(args.num_layers-1):
            self.convs.append(conv_model(args.heads * hidden_dim, hidden_dim))
        # post-message-passing
        self.post_mp = nn.Sequential(
            nn.Linear(args.heads * hidden_dim, hidden_dim), nn.Dropout(args.dropout),
            nn.Linear(hidden_dim, output_dim))
        self.dropout = args.dropout
        self.num_layers = args.num_layers
        self.emb = emb

    def build_conv_model(self, model_type):
        if model_type == 'GraphSage':
            return GraphSage
        elif model_type == 'GAT':
            # When applying GAT with num heads > 1, you need to modify the
            # input and output dimension of the conv layers (self.convs),
            # to ensure that the input dim of the next layer is num heads
            # multiplied by the output dim of the previous layer.
            # HINT: In case you want to play with multiheads, you need to change the for-loop that builds up self.convs to be
            # self.convs.append(conv_model(hidden_dim * num_heads, hidden_dim)),
            # and also the first nn.Linear(hidden_dim * num_heads, hidden_dim) in post-message-passing.
            return GAT

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        for i in range(self.num_layers):
            x = self.convs[i](x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout,training=self.training)
        x = self.post_mp(x)
        if self.emb == True:
            return x
        return F.log_softmax(x, dim=1)

    def loss(self, pred, label):
        return F.nll_loss(pred, label)
```

## Q1: Creating Our Own Message Passing Layer

首先复习一下 GraphSAGE 的实现：

