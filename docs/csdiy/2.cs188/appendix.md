> [Logic](https://inst.eecs.berkeley.edu/~cs188/textbook/logic/)

10.1这段话非常生动，摘录于此（中文是自己手动翻译的）：

> Imagine a dangerous world filled with lava, the only respite a far away oasis. We would like our agent to be able to safely navigate from its current position to the oasis.
>
> 想象一个离一片绿洲不远，但却充满岩浆的危险环境。现在我们希望我们的agent能够从当前位置安全地抵达绿洲。
>
> In reinforcement learning, we assume that the only guidance we can give is a reward function which will try to nudge the agent in the right direction, like a game of ‘hot or cold’. As the agent explores and collects more observations about the world, it gradually learns to associate some actions with positive future reward and others with undesirable, scalding death. This way, it might learn to recognize certain cues from the world and act accordingly. For example, if it feels the air getting hot it should turn the other way.
>
> 在强化学习中，我们设定唯一能给予的引导是一个能将agent推向正确方向的奖励函数，就像"hot or cold"游戏的玩法一样（详见[Hot and Cold game - How to play ? - Party Games 4 Kids](https://partygames4kids.com/hot-and-cold-game)）。当agent在探索中获得了对这个世界的些许洞察后，它会逐步将可能获得的收益或者负面乃至烫伤致死的后果与某些行为联系在一起。在这样的情况下，它将学会辨别这个世界给予的诸多线索，并作出相应的举动。比如，如果感受到周围的空气正在升温，那么它将会调转方向前进。
>
> However, we might consider an alternative strategy. Instead, let’s tell the agent some facts about the world and allow it to reason about what to do based on the information at hand. If we told the agent that air gets hot and hazy around pits of lava, or crisp and clean around bodies of water, then it could reasonably infer what areas of the landscape are dangerous or safe based on its readings of the atmosphere. This alternative type of agent is known as a **knowledge-based agent**. Such an agent maintains a **knowledge base**, which is a collection of logical **sentences** that encode what we have told the agent and what it has observed. The agent is also able to perform **logical inference** to draw new conclusions.
>
> 然而，我们也可以考虑另一种策略。与先前不同的是，我们可以将世界上的许多事实告知给agent，并且让它基于已知事实推理出下一步该做什么。如果我们告诉agent，空气在熔岩坑的附近会变得又热又浑浊，而在水源附近会变得清凉洁净，那么它可以依据对周围空气状态的识别，合理推断出某片区域安全与否。这种agent类型我们称之为知识库驱动的agent。它拥有知识库，一个将我们事先告诉它的知识以及它观察到的知识编码成逻辑语句的庞大集合。它还能通过逻辑推理，给出新的结论。

10.2：温习一下英语

> $\neg$ : `\neg`, not 
>
> $\lor$: `\lor`, or, aka "disjunction"
>
> $\land$: `\land`, and , aka "conjunction"
>
> $\Rightarrow$: `\Rightarrow`, implication
>
> $\Leftrightarrow$: `Leftrightarrow`, biconditional

10.3: Propositional Logic

> Propositions: 陈述/命题
>
> 
>
> 



