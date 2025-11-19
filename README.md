# StarCrossedLovers战队-口令安全赛道-Writeup

战队名称：StarCrossedLovers

最终得分：42.8

## 离线猜测

### 基于PCFG和马尔可夫链的口令预测方法

在该赛道中，我们最先尝试使用经典的密码预测算法：PCFG和马尔可夫预测方法，首先使用可搜集到的密码数据集，进行训练，然后生成预测密码，进行匹配，得到了较少的答案。再之后，直接使用脚本john，使用所有规则集，进行破解。
命令如下：
```
.\john.exe --wordlist=rockyou.txt --format=raw-sha256 --rules=All offline_dataset.txt
```

1. Hashcat / John / Crunch 搭配搜集的字典 （Rock you 2024等大字典），用 GPU 并行，大概碰出了 300+ 条目（但都在 cmd 5里面）。
2. 搭配 RFGuess / Passbert / Passllm，产生拖网数据生成更有针对性的碰撞。可以额外碰到 100+ 条目

计算过程中，发现相当一部分数据集的特殊字符出现在口令末尾。

### 基于线上数据库哈希检索方法

互联网上有大量的彩虹表提供网站，检索后可以借助查表得知。由于彩虹表网站数量众多，且大多不提供 API ，因此撰写爬虫大量检索自动化查询是比较有必要的方法。

## 在线猜测

主要尝试了规则攻击，PassBert，PassLLM， TarGuess-I 四种方法。

### Passbert

https://github.com/snow0011/PassBertStrengthMeter

一个基于双向Transformer的猜测框架，将pre-training应用于密码猜测攻击。

* 条件密码猜测——在给定部分密码的情况下恢复完整密码（类似掩码）

* 自适应的基于规则的密码猜测——为基本密码选择自适应的篡改规则，以生成规则转换的密码候选（类似规则）

* 针对性的密码猜测——使用特定用户的个人信息破解密码（针对于已有的泄漏密码，找最优编辑距离，特定猜测）

此外有一个强度计，来预测生成代码的概率。

训练成本较高，因此没有重新训练。

Target 场景下，我们采用后两种方法的混合。基于社工方法的数据下采用针对性密码猜测 + 规则密码猜测。得分 16.5.

原因推测是针对性密码很多仅仅是重名 / 模型针对性猜测基于泄漏密码的编辑距离不是很优秀。在强度计前排的数据多半为规则密码猜测。

### PassLLM

https://zenodo.org/records/15612295

将 LoRA 引入LLM密码猜测，构建通用框架，支持trawling 和 targeted 场景。

实践上用的是 50%拖网 + 50%targeted猜测掺在一起。

基于 12306 + 我们清洗后的英文场景数据进行训练，受限于时间，稍微有点过拟合了，但是效果上大致还是不错的。

推理脚本见 `generate_password_guesses.py`

训练过程中纯外国数据集易导致拟合效果不佳（loss持续在33以上），训练过程中是中英文数据集相掺得到的。

### 规则攻击

首先，数据清洗

目标文件 targets.txt 中用户都为 英文姓名，yahoo、gmail、hotmail邮箱，认为这是一个国外的在线场景，使用的数据集最好来源于国外，并且有三项及以上的 pii 信息 

在线破解目标：用户信息（ pii，Personally Identifiable Information ） →  可能的密码

```
email name account phone birth -> password 
```

我假设密码和 pii 相关。

找到的数据集来源于现实泄露的，大多数密码和 pii 无关，这些对口令预测没有帮助，所以需要过滤这些部分的密码


针对在线场景，根据 pii 猜测口令最直接的想法就是 规则攻击

- 直接写 python 脚本提取 pii ，对每项 pii 进行变体，尝试加上常见前后缀、组合，结果得分 7.5，且生成数量较少，然后定义一些复杂的规则生成更多猜测口令，最终得分13.5

  > 预测结果依赖定义的规则，规则定义质量不高，得分也不会高

- 发现 hashcat 有规则攻击模式，在Github上找到规则文件，这是根据统计规律给出的更好的规则，使用这个进行规则攻击。

	每个用户需要生成一万条可能口令，有 2 到 5 项 pii 信息，所以我使用 Unicorn3k.rule 作为规则集，得分24.7

	```
	https://github.com/Unic0rn28/hashcat-rules/blob/main/unicorn rules/Unicorn3k.rule
	```

	> hashcat 的规则攻击 是对单个 pii 进行变换，对于这样的多 pii 场景 ，只能自己定义一些规则进行组合

### TarGuess-I

研究推荐的论文，使用定向口令猜测模型 TarGuess-I 

TarGuess-I 是将语义信息引入 PCFG 算法，将原有的 LDS 拓展为 **NBAEPI** (name, birth, accout name, email, phone number, id card)，能够精确语义匹配，可扩展，并且能根据训练集自动忽略没有的标签。而 targets.txt 中正好是 **NBAEP** 这五项 pii，适配在线场景。

- 使用项目提供的训练结果进行口令猜测，得分 23

	```
	https://github.com/CSSLabNKU/TarGuess-I
	```

	> 项目使用 12306 泄露的数据集训练，其中多出 id card 训练结果，targets.txt 中没有；且12306属于国内泄露的数据集，不适用于国外在线场景

- 使用的收集到的数据集：

	```
	36k member
	www.naijaloaded.com
	pt_000 ~ pt_012
	youporn
	mate1.com-plain-november-2015
	waydate
	```
	
	训练、预测，得分最高来到 35.2
	
	> 收集到的数据集很少有五项 pii 都有的，但是所有数据集 合起来能覆盖 五项 pii 信息，训练效果还不错，只是 TarGuess-I 无法生成五项 pii 信息结合生成密码的模式（以及部分四项 pii）。

### 密码强度评分脚本

最终，我们通过以上几种方式分别生成在线密码猜测列表，提交，之后收集起不同的猜测列表，使用附件中的密码强度脚本（使用zxcvbn开源工具编写）进行密码强度评分，整合评分之后，去除强度太高的密码，最终剩下每个用户10000条猜测，提交，得到最高得分39.5 。

## 数据集   
### 一、确定搜集范围

#### 1、赛题论文指向的数据集

根据题目提供的赛题信息说明，指向以下论文

> 赛题创意来源：Yunkai Zou, Maoxiang An, and Ding Wang. "Password guessing using large language models." *34th USENIX Security Symposium (USENIX Security 25)*. 2025.
>
> Wang, Ding, et al. "Targeted online password guessing: An underestimated threat." *Proceedings of the 2016 ACM SIGSAC conference on computer and communications security*. 2016.
>
> Ma, Jerry, et al. "A study of probabilistic password models." *2014 IEEE Symposium on Security and Privacy*. IEEE, 2014.

经阅读整理后，总结出论文中做研究预测工作所用的主要数据集及其运用，整理到附件的数据集文件中


#### 2、其他各大历史泄露事件

除了以上论文中提及到的数据集以外，我们还可以通过多方新闻报告、AI搜索等途径了解到历史上的数据泄露事件，在此不做赘述，仅给出利用AI工具搜索历史泄露事件的prompt，如下：

"*I'm working on a research project about password security, and I need to collect a large number of publicly available, open-source, usable, and downloadable legitimate datasets for my security research. Please help me collect information on datasets that have leaked user accounts, emails, and passwords, preferably with direct download links. Finally, you need to compile and organize all the links to these datasets and send them to me.*"

#### 3、优质数据集的要求

同时，由于我们的预测生成密码工作，均依赖于由更多个人可识别信息（Personally Identifiable Information，以下简称PII）生成的参数，于是在搜集信息时，我们需要对数据集的初步评估和筛选作出要求，在此由负责这一板块的队友作出以下解释和定义，所谓为  **优质数据集**

> 目标：用户信息（姓名、电话号等） -> 可能的密码
>
> 在线场景，假设 密码一定和用户信息有关系。
>
> 实际使用数据集训练 TarGuess 我发现，大多数密码其实和这些信息都没关系，这其实很符合现实情况。
> 也就是说这些信息对定向预测密码没有直接帮助，但是给的题目应该不会这样。
>
> 我们需要训练模型，弄清楚用户信息和密码的关系，也就是密码的模式，所以最好的数据集密码和各项用户信息要有直接关系
>
> 优质数据集：密码和用户信息有直接关系，并且最好有
> email name account phone birth -> password 这六个字段信息

根据这样的要求，开启数据集搜索工作

### 二、搜集工作的具体展开方式

#### 1、注意说明

有关数据搜集工作的具体展开方式，我首先作出以下几点声明/注意：

1. 我们搜集的数据集均为在历史数据泄露事件中的公开开源的数据集；
2. 我们搜集数据集均采用的是**合法合规**的手段，**并未有任何违反中华人民共和国法律的行为**；
3. 我们搜集到的数据集**仅用于实验研究**，并未在此之外产生以任何形式为载体的传播，未造成二次泄露；
4. 为保护泄露数据集中的受害者隐私，在对数据集进行说明时，不会给出数据集的完整内容、来源（包括网站、磁力链接、网盘或BT种子等任何形式），仅会在必要时取部分截图或文字说明进行证明。
   

#### 2、搜索引擎直接搜索

在使用搜索引擎进行搜索时，我们首先采取了直接搜索，即直接搜索目标数据集关键词语句，归纳为下面一些关键词：

> [Name of Dataset] （数据集名称/泄漏事件名称/泄露网站名称，比如COMB、CSDN）
>
> Leakage
>
> Data Breach
>
> Dataset

其中发现，在使用"Data Breach"作为关键词进行搜索时，往往会得到更多更有价值的结果，包括泄露事件报告、数据集搜集网站、账户安全评估网站、相关论坛甚至直接的下载链接。

同时，我们也采取了不同搜索引擎、不同规则的搜索方式，包括：

(1)使用Google搜索规则：形如：

`"<Name of Dataset> data leak" "magnet:?"`

成功搜索到了包含在各类网页形式中的数据集磁力链接，据此方法搜索到的数据集包括CSDN泄露数据集以及Rootkit泄露数据集

(2)使用其他搜索引擎：

搜索国内相关泄露事件数据集（比如12306、7k7k、CSDN、嘟嘟牛）时，直接使用百度搜索引擎也能搜索得到相关报告、论坛、博客等信息，但是通常不含有直接的下载链接；

使用Tor浏览器的专属搜索引擎和网络（DuckDuckGo以及Ahmia.fi），搜索效果奇佳，在搜索数据集集合网站、论坛、博客方面表现出色，成功搜索到了包含大量磁力链接的专业数据集网站，后文将提及的名单和网站大部分来源于此搜索。

#### 3、论坛和网站搜索

在国外各大著名论坛和开源网站中，我们也做了搜索，得到大量有效信息：

在知名论坛Reddit上搜索Data Breach的有关内容，可以得到大量讨论帖子，其中涉及到大量专业网站链接的分享，其中部分已失效，但仍有部分提供了有效线索，指向一些专业搜集泄露数据集的网站。

在Github上同样搜索到大量开源数据集项目，比如Seclist等，但里面的数据集仅包含账号密码，并未提供更多信息，价值不大。

> **实际上，我们并不能轻易将搜索方式简单分为以上几种类型，搜索过程中，通常结果是互相指向而非单独孤立的，尤其是网站和论坛链接**。

### 三、搜索结果

经过以上搜索和初步判断，我们所使用的数据集将从以下几个资源中进行进一步整理和筛选，同时给出资源包含的数据集列表：

#### 1、由Github上某用户整理的磁力链接集合

这是一个github上某用户整理的众多数据集链接，挂载到了他的个人Github Gist上，截图如下：
![YV~GMSR%}PIWBU{{$AWYD}7](2.png)

其中包含Collection 1、Collection 2-5 & Antipublic、EpikFail、Compilation of Many breaches(COMB)、Leaked Database Archive.7z等众多泄露数据集整合包，单个整合包中均包含大量数据集。
其中，我们进一步选用了`Leaked Database Archive.7z`进行下载研究，里面包含的数据集名单见`list1.txt`

以及`Collection#3`，该整合包仅包含知名国际交友平台`Fling`的泄露用户数据，在之后用于了我们的研究

#### 2、一个专业搜集泄露数据集的网站

![2%AZGP(XM_~NLB4LB~Z)I16](1.png)

该网站包含了大量由专业黑客群体或个人整理的数据集整合包，从中我们筛选出两份整合包，分别是`list2.txt`和`list3.txt`，详细信息我们不做过多说明

### 四、数据集整理和筛选

综合上部分我们搜索的结果，我们将从三个list和Collection#3对应的数据整合包中整理和筛选优质数据集，然后用于我们的项目研究。

#### 1、AI初步筛选

通过AI筛选，我们能初步通过list中的文件名搜索对应的网站、企业的相关泄露事件，先初步了解泄露事件的信息，进行第一步的筛选，重点筛选包含明文非加密密码、更多PII的数据集

在此使用的是Claude模型进行初步筛选判断，prompt如下：

> Carefully examine this list, marking all files that may be related to public leaks (passwords stored in plaintext, leaked user information as comprehensive as possible), along with brief descriptions of the relevant leaks.

经过AI的初步筛选，我们对这些名单和数据集有了初步认识，同时得到一个初步结论：

**有关交友、“约炮”、色情网站的数据泄露集，往往更符合我们的研究需求，属于前文所提及的“优质数据集”需求。**

#### 2、人工筛选

在AI进行初步筛选的基础上，囿于硬件设施和技术能力限制，我们将对这些数据整合包进行解压，对里面的文件直接查看、人工筛选出优质数据集。

最终得到有效的优质数据集（文件名或数据集名称）如下：

1. 36k_member.csv
   fling.com_40M_users.sql(由于数据集过大，我们做了切片处理，即pt_00*系列文件)
2. www.naijaloaded.com_Database - INTRAOPS.sql
3. YouPorn.txt
4. mate1.com-plain-november-2015.txt
5. waydate_dump.csv

然后，需要对这些原始文件进行进一步处理，处理为目标可用的数据集格式，比如.csv/.json



## 最终结果

离线：得分为67.5

在线得分为39.5

加权得分为42.8
