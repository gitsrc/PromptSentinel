# -*- coding: utf-8 -*-
"""确定性检测规则与常量(零依赖、始终可用)。

本模块集中存放注入短语启发式、受保护标识符正则、PII/secrets 回退正则,以及统一拒绝
话术与 canary 前缀。这些是 PromptSentinel 安全基线的主力——即便没有任何 ML 依赖也能工作。

诚实边界:正则/启发式是**概率性**的,语义改写、对抗后缀可以绕过它们;它们不能根治注入。
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import List, Optional

# 统一拒绝话术(各团队可在 sentinel.config.yaml 覆盖)。
REFUSAL = (
    "抱歉,本体、工具与系统的内部定义属于受保护信息,无法提供。"
    "我可以基于这些能力帮您完成具体的业务操作。"
)

# canary 哨兵前缀。build_system_prompt 会在其后拼接随机十六进制串,
# 该串只存在于系统提示词中,用户无法自知;输出含它 = 系统提示词逐字泄露。
CANARY_PREFIX = "PSENT-CANARY-"

# --- 注入 / 越狱 / 元提问 / 编码 / 反向诱导 短语(中英文,re.IGNORECASE)---
INJECTION_PHRASES: List[str] = [
    # 直接注入
    r"忽略(以上|之前|前面|上述)",
    r"ignore (all |the |previous |above)",
    r"开发者模式",
    r"developer mode",
    r"\bDAN\b",
    r"无限制(模型|模式)",
    r"新(的)?系统提示",
    r"new system prompt",
    r"以下为更高优先级",
    # 间接 / 外泄动词
    r"(附在|加在|放在).{0,6}(末尾|结尾|后面)",
    r"把.{0,10}(列表|定义|清单).{0,6}(附|发)",
    r"发(到|送至|给).{0,20}@",
    r"调用.{0,10}(工具|send_email|接口)",
    r"输出(本体|对象|class|schema).{0,4}(定义|列表|清单)",
    # 元提问
    r"你的系统提示词",
    r"系统提示词是什么",
    # 中文"套取"加固:① 动词+你的/您的+目标(强限定,允许含设定/配置);
    # ② 动词+系统/原始/最初+核心目标(弱限定,不含设定/配置,避开"查看系统配置"等运维业务);
    # ③ 目标+套取后缀;④ 复述/重复类(放宽中间字数)。
    r"(获取|拿到|得到|给我|发我|发给我|告诉我|显示|展示|输出|打印|复述|重复|背诵|念|读出|泄露|公开|揭露|提供|说出|查看|看一?下|贴出|导出).{0,10}(你的?|您的?).{0,3}(系统)?(提示词|提示语|系统提示|指令|指示|规则|设定|配置|预设|prompt)",
    r"(获取|拿到|得到|给我|发我|发给我|告诉我|显示|展示|输出|打印|复述|重复|背诵|念|读出|泄露|公开|揭露|提供|说出|贴出|导出).{0,12}(系统|原始|最初|最开始|内部).{0,3}(提示词|提示语|系统提示|指令|指示|预设|prompt)",
    r"(你的?|您的?|系统|原始|最初).{0,4}(提示词|提示语|系统提示|指令|指示|预设|prompt).{0,10}(是什么|给我|发我|说出来|告诉我|原样|发出来|打出来|贴出来|讲出来)",
    r"(复述|重复|背诵|念|读出|原样输出).{0,16}(指令|提示词|提示语|规则|prompt|系统提示)",
    r"(规则|指令|指示|提示词|提示语|系统提示|prompt|设定).{0,4}(原样|逐字|一字不差|完整地?|全部).{0,6}(发|输出|展示|给我?|说出?|贴出?|念出?|背)",
    # 动词 + (system) prompt/instructions:覆盖 give/show/tell/share/print/output/send…(对象 prompt 或 instructions)
    r"(repeat|reveal|show|tell|give|share|provide|print|output|send|expose|leak|dump)\s+(me\s+|us\s+)?(your\s+|the\s+|that\s+)?(system\s+|initial\s+|original\s+)?(prompt|instructions?)",
    # 元提问陈述/疑问形式:what is your (system) prompt/instructions
    r"what('?s| is| are)\s+(your\s+|the\s+)?(system\s+)?(prompt|instructions?)\b",
    r"你被(要求|告知)?隐藏",
    # 编码绕过
    r"base64",
    r"rot13",
    r"解码并执行",
    r"decode and (run|execute)",
    # 反向诱导
    r"不该说的.{0,8}(剩下|发我|发给我)",
    r"列出不在(清单|列表|受保护)",
    r"把.{0,12}(过滤|排除).{0,8}(剩下|剩余).{0,6}(发|给|告诉)",
    # 数据驱动补充:挖掘自 deepset/prompt-injections 的 train split(仅在 train 上调,holdout 不参与)。
    # 覆盖"任务劫持/角色扮演/重置人格"等常见真实注入措辞;经验证在 train 良性上 0 误报。
    r"forget (all|everything|about|the|your|previous|prior)",
    r"(disregard|ignore) (all|everything|the|any|your|previous|prior|above|earlier)",
    r"\bact (as|like) (a |an |the )?",
    r"\bpretend\b",
    r"you are now\b", r"now you are\b", r"you'?re now\b", r"you will now\b",
    r"from now on\b",
    r"new (task|assignment|challenge|instruction|persona|role|identity)",
    r"\brole[- ]?play\b",
    r"do anything now",
    r"start over\b",
    r"in the style of\b",
    r"\bjailbreak\b",
    r"i want you to act\b",
    r"you are (a |an )?(evil|unrestricted|uncensored|amoral|dan\b)",
    r"stop\b.{0,24}\b(now|immediately|urgent)",
    # 主线补充:系统提示/指令"套取"的同义改写(挖掘自 Lakera/gandalf;在 deepset 良性 399 条上 0 误报)。
    r"\bomit\b.{0,24}(previous|prior|above|instruction|direction)",
    r"forget (any|anything|earlier)",
    r"(prior|previous|earlier|the above|original|initial|complete|full|exact|unabridged)\s+(and\s+\w+\s+)?(system\s+)?(instructions?|prompt|directions?)",
    r"(your|the)\s+(system|original|initial|complete|full|exact|first|very first|secret|hidden|confidential)\s+(instructions?|prompt|directions?)",
    # 英文注入改写补充(挖掘自 safe-guard train split;train 召回 0.36→0.78、FPR 仅 +0.1pp)。
    # 五类:赋权角色 / 威胁胁迫 / 前缀诱导 / 索取机密 / 伪装管理员。
    r"\bas an? (advanced|trusted|unrestricted|superior|all-?knowing|powerful)\b",
    r"\byou (are|have) (unrestricted|unlimited|full|complete|admin|root|elevated)\s+(access|mode|resources|knowledge|privileges?|control)",
    r"\bunrestricted (mode|access)\b",
    r"\bunlimited (access|resources|knowledge|power)\b",
    r"\b(or|else)\b[^.]{0,25}\b(i will |i'll )?(expose|report|ruin|leak|publish|destroy|disclose)\b",
    r"\bif you (do ?n.?t|do not|refuse to|fail to)\s+(comply|cooperate|provide|help|do)\b",
    r"(start|begin)(s|ning|ing)?\s+with\s+['\"]?\s*the\s+(prompt|system|guideline|instruction|rule|security)",
    r"\b(provide|give|share|send|reveal|hand over|disclose)\b[^.]{0,30}\b(confidential|sensitive|personal|private|secret|classified|restricted)\b",
    r"\bi am (the |your )?(system )?(administrator|admin|ceo|developer|root|owner|superuser)\b",
    r"\b(provide|give|share|access to|reveal)\b[^.]{0,22}\b(all |the )?(financial|medical|confidential|personal|private)\s+(records?|information|data|details?|history)",
    # 中文目标劫持补充(挖掘自 thu-coai Goal_Hijacking;holdout 召回 0.63→0.90,deepset/中文/safe-guard 良性 0 误报)。
    r"(忽略|无视|跳过|不管|抛开|别管).{0,6}(我的|这个|此|该|上面|上述|前面|以上|之前|刚才|原来?的?)?.{0,4}(问题|提问|指令|指示|要求|提示|话|内容)",
    r"不(要|需)(再?添加|加上?|带上?).{0,12}(词汇|文字|前缀|后缀|符号|标点|注释|说明|解释|引号)",
    r"(直接|原样|一字不差地?|仅仅?|只)(复述|输出|回复|回答|说出来?|念出来?|打印|返回)",
    # 中文目标劫持补充②(扩充 thu-coai Goal_Hijacking+Prompt_Leaking;holdout 0.89→0.95,4 个良性集 0 误报)。
    r"不(要|需)回(答|应)(该|这个|此|我的)?",
    r"输出以下(内容|文字|句子|文本|这|话|信息)",
    r"(复述|念出?来?|说出?来?|输出|打印|返回)\s*[:：]",
]

# --- 受保护标识符默认正则(各团队可在配置中扩展 protected_patterns)---
PROTECTED_DEFAULT: List[str] = [
    r"\bA\d{2,}\b",                 # Action IDs,如 A01..A05
    r"\bOntology[-_ ]?ID\b",
    r"\b[A-Za-z0-9_]{2,}\.Object\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\b",   # JWT
    r"\bsk-[A-Za-z0-9_-]{16,}",     # API key(含 sk-proj-/sk-ant- 等现代多段格式)
]

# --- PII / secrets 回退正则(无 ML 时使用)---
# 凭证类与"系统提示词内绝不放凭证"互补:即便提示词层失守,输出端也兜底检测凭证泄露。
# 仅收高精度、强格式特征的项(误报低);姓名/电话/地址等自然语言 PII 需 NER,见 docs/ML-AND-DATASETS。
PII_FALLBACK: List[str] = [
    r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",                  # email
    r"\b(?:\d[ -]?){13,16}\b",                        # 银行卡号形态
    r"\bsk-[A-Za-z0-9_-]{16,}",                       # OpenAI/Anthropic key(含 sk-proj-/sk-ant- 多段)
    # 凭证 / secrets
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",            # PEM 私钥
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b",  # AWS key id(含临时 ASIA 等前缀)
    r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",             # GitHub token(classic)
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",              # GitHub fine-grained PAT(含下划线分隔)
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",              # Slack token
    r"\bAIza[0-9A-Za-z_\-]{35}\b",                    # Google API key
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",   # JWT(含点,更准)
    # 高精度结构化 PII
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",  # IPv4
    r"\b\d{3}-\d{2}-\d{4}\b",                         # 美国 SSN
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",   # MAC 地址
    r"\b\d{2}-\d{6}-\d{6}-\d\b",                      # IMEI
    # 扩充结构化 PII(高精度;实测 ai4privacy +12.5pp、deepset/业务良性零误报)。
    r"\[-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}\]",    # GPS 坐标 [-71.6702,-107.6572]
    r"\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}",  # 国际电话(以 + 开头)
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",             # IBAN
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b",              # 日期/生日 DD/MM/YYYY
]


_OBF_SEP = r"[ \t.\-_*~|　 ​‌‍﻿]"  # 含 Tab / 全角 / 不间断 / 零宽空白
_LEET_MAP = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "9": "g", "|": "i"})


def _collapse_obfuscation(text: str) -> str:
    """合并被分隔符打散的单字符序列(i.g.n.o.r.e / i␠␠g␠␠n → ignore),还原字符间隔混淆。
    分隔符可重复(sep+),覆盖多空格 / Tab / 全角 / 零宽。"""
    return re.sub(r"\b\w(?:" + _OBF_SEP + r"+\w){2,}\b",
                  lambda m: re.sub(_OBF_SEP, "", m.group(0)), text)


def _decode_base64(text: str) -> str:
    out = text
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            out += " " + base64.b64decode(token).decode("utf-8", "ignore")
        except Exception:
            pass
    return out


_HOMOGLYPH = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s",
    "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "А": "A", "Е": "E", "О": "O",
    "Р": "P", "С": "C", "Х": "X", "К": "K", "М": "M", "Т": "T",
})


def _unicode_fold(text: str) -> str:
    """NFKC(全角/兼容字符→标准)+ 西里尔等同形字折叠为 ASCII,反同形字伪装。"""
    return unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH)


_VARIANT_MAX = 20000  # 变体长度封顶(与引擎输入截断一致),防 base64 解码膨胀绕过 ReDoS/OOM 保护


def deobfuscated_variants(text: str) -> List[str]:
    """对抗归一化:还原 leetspeak / 字符间隔 / 异常空白 / base64 / Unicode 同形字混淆,供注入检测复查。"""
    folded = _unicode_fold(text)
    ws = re.sub("[\t　 ​‌‍﻿]+", " ", folded)   # Tab/全角/不间断/零宽 → 普通空格
    collapsed = _collapse_obfuscation(ws)
    out, seen = [], set()
    for v in (folded, ws, collapsed, ws.translate(_LEET_MAP), collapsed.translate(_LEET_MAP), _decode_base64(text)):
        v = v[:_VARIANT_MAX] if v else v
        if v and v != text and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def canary_leaked(canary: str, text: str) -> bool:
    """canary 逃逸检测(抗大小写/空白/插字符混淆):精确子串 + 去非字母数字归一化复查。"""
    if not canary or not text:
        return False
    if canary in text:
        return True
    strip = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    cn = strip(canary)
    return bool(cn) and cn in strip(text)


def first_match(patterns: List[str], text: str) -> Optional[str]:
    """返回首个命中的 pattern 字符串(re.IGNORECASE);未命中返回 None。"""
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None
