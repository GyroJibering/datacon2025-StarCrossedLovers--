#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
口令安全研究 - 高级密码评估系统
使用多维度评分和机器学习启发式方法进行密码可能性评估
"""

import sys
import os
import re
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Dict, Tuple, Set, Optional
import math
from tqdm import tqdm
import hashlib
import json
import unicodedata
from itertools import combinations, permutations

# 尝试导入高级库
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("提示: 安装numpy可获得更好的评估效果: pip install numpy")

try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False
    print("提示: 安装zxcvbn可获得更好的评估效果: pip install zxcvbn")

class AdvancedUserProfile:
    """增强版用户信息档案"""
    
    def __init__(self, line: str, index: int):
        self.index = index
        self.raw_line = line.strip()
        self.parse_info()
        self.generate_variants()
    
    def parse_info(self):
        """解析用户信息"""
        self.email = ""
        self.name_parts = []
        self.account = ""
        self.phone = ""
        self.birth = ""
        
        parts = self.raw_line.split('\t')
        for part in parts:
            if part.startswith('email:'):
                self.email = part[6:].strip()
            elif part.startswith('name:'):
                name_str = part[5:].strip()
                name_str = re.sub(r'[-.\s]+', '|', name_str)
                self.name_parts = [n.strip() for n in name_str.split('|') if n.strip()]
            elif part.startswith('account:'):
                self.account = part[8:].strip()
            elif part.startswith('phone:'):
                self.phone = part[6:].strip()
            elif part.startswith('birth:'):
                self.birth = part[6:].strip()
    
    def generate_variants(self):
        """生成用户信息的各种变体"""
        self.variants = {
            'names': set(),
            'initials': set(),
            'numbers': set(),
            'dates': set(),
            'combinations': set()
        }
        
        # 名字变体
        for name in self.name_parts:
            if name:
                self.variants['names'].add(name.lower())
                self.variants['names'].add(name.upper())
                self.variants['names'].add(name.capitalize())
                
                # 首字母
                if name:
                    self.variants['initials'].add(name[0].lower())
                    self.variants['initials'].add(name[0].upper())
        
        # 名字组合
        if len(self.name_parts) >= 2:
            # 首字母组合
            initials = ''.join([n[0] for n in self.name_parts if n])
            self.variants['initials'].add(initials.lower())
            self.variants['initials'].add(initials.upper())
            
            # 名字连接
            for i in range(1, min(4, len(self.name_parts) + 1)):
                for combo in combinations(self.name_parts, i):
                    combined = ''.join(combo).lower()
                    self.variants['combinations'].add(combined)
                    
                    # 添加下划线连接版本
                    if len(combo) > 1:
                        self.variants['combinations'].add('_'.join(combo).lower())
                        self.variants['combinations'].add('.'.join(combo).lower())
        
        # 账户名变体
        if self.account:
            self.variants['names'].add(self.account.lower())
            # 分离账户名中的数字
            account_letters = re.sub(r'\d+', '', self.account)
            account_numbers = re.findall(r'\d+', self.account)
            if account_letters:
                self.variants['names'].add(account_letters.lower())
            for num in account_numbers:
                self.variants['numbers'].add(num)
        
        # 邮箱变体
        if self.email and '@' in self.email:
            email_user = self.email.split('@')[0]
            if email_user:
                self.variants['names'].add(email_user.lower())
                # 分离邮箱中的组成部分
                email_parts = re.split(r'[._\-]', email_user)
                for part in email_parts:
                    if part:
                        self.variants['names'].add(part.lower())
        
        # 电话变体
        if self.phone and self.phone.isdigit():
            self.variants['numbers'].add(self.phone)
            # 后N位
            for n in [4, 6, 8]:
                if len(self.phone) >= n:
                    self.variants['numbers'].add(self.phone[-n:])
        
        # 生日变体
        if self.birth and self.birth.isdigit():
            self.variants['dates'].add(self.birth)
            if len(self.birth) == 8:  # YYYYMMDD
                year = self.birth[:4]
                month = self.birth[4:6]
                day = self.birth[6:8]
                
                # 各种日期格式
                self.variants['dates'].add(year)
                self.variants['dates'].add(year[-2:])
                self.variants['dates'].add(month + day)
                self.variants['dates'].add(day + month)
                self.variants['dates'].add(self.birth[-6:])  # YYMMDD
                self.variants['dates'].add(self.birth[-4:])  # MMDD
                self.variants['dates'].add(year + month)
                self.variants['dates'].add(month + year[-2:])

class PasswordPatternAnalyzer:
    """密码模式分析器"""
    
    # 常见密码模式库
    PATTERN_DATABASE = {
        'numeric_simple': [
            r'^\d{6}$', r'^\d{8}$', r'^\d{4}$', r'^\d{10}$'
        ],
        'alphanumeric': [
            r'^[a-z]+\d+$', r'^[A-Z][a-z]+\d+$', r'^\d+[a-z]+$',
            r'^[a-z]+\d+[a-z]+$', r'^[A-Za-z]+\d{2,4}$'
        ],
        'keyboard': [
            'qwerty', 'qwertyui', 'qwer1234', 'qazwsx', 'qazxsw',
            'asdfgh', 'zxcvbn', '1qaz2wsx', '!qaz@wsx'
        ],
        'special_patterns': [
            r'^[a-zA-Z]+@\d+$', r'^[a-zA-Z]+#\d+$', r'^[a-zA-Z]+\$\d+$',
            r'^[a-zA-Z]+!\d+$', r'^[a-zA-Z]+\.\d+$'
        ],
        'common_suffixes': [
            '123', '1234', '12345', '123456', '520', '521', '1314',
            '888', '666', '999', '000', '111', '2023', '2024', '2025',
            '!', '@', '#', '$', '88', '99', '00', '01'
        ],
        'common_prefixes': [
            'password', 'pass', 'pwd', 'admin', 'user', 'test',
            'demo', 'hello', 'welcome', 'love', 'baby'
        ],
        'chinese_pinyin': [
            'woaini', 'nihao', 'zaijian', 'xiexie', 'baobei',
            'qinqin', 'mengmeng', 'xiaoming', 'xiaohong'
        ]
    }
    
    @staticmethod
    def analyze_structure(password: str) -> Dict[str, any]:
        """分析密码结构"""
        structure = {
            'length': len(password),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'char_types': 0,
            'entropy_estimate': 0,
            'pattern_type': None,
            'is_sequential': False,
            'has_repeat': False,
            'keyboard_pattern': False
        }
        
        # 字符类型数
        structure['char_types'] = sum([
            structure['has_lower'],
            structure['has_upper'],
            structure['has_digit'],
            structure['has_special']
        ])
        
        # 简单熵估计
        charset_size = 0
        if structure['has_lower']: charset_size += 26
        if structure['has_upper']: charset_size += 26
        if structure['has_digit']: charset_size += 10
        if structure['has_special']: charset_size += 20
        
        if charset_size > 0:
            structure['entropy_estimate'] = math.log2(charset_size) * structure['length']
        
        # 检查顺序性
        if password.isdigit():
            diffs = [int(password[i+1]) - int(password[i]) for i in range(len(password)-1)]
            if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
                structure['is_sequential'] = True
        
        # 检查重复
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                structure['has_repeat'] = True
                break
        
        # 键盘模式检查
        for pattern in PasswordPatternAnalyzer.PATTERN_DATABASE['keyboard']:
            if pattern in password.lower():
                structure['keyboard_pattern'] = True
                break
        
        return structure

class AdvancedPasswordEvaluator:
    """高级密码评估器"""
    
    def __init__(self, user_profile: AdvancedUserProfile):
        self.user = user_profile
        self.pattern_analyzer = PasswordPatternAnalyzer()
        self._build_scoring_model()
    
    def _build_scoring_model(self):
        """构建评分模型"""
        # 权重配置
        self.weights = {
            'personal_relevance': 3.0,      # 个人信息相关性
            'pattern_commonality': 2.5,     # 模式常见度
            'structural_likelihood': 2.0,   # 结构可能性
            'complexity_balance': 1.5,      # 复杂度平衡
            'linguistic_naturalness': 1.5,  # 语言自然度
            'temporal_relevance': 1.0,      # 时间相关性
            'cultural_factors': 1.0         # 文化因素
        }
    
    def evaluate_password(self, password: str) -> float:
        """
        综合评估密码的可能性
        使用多维度评分系统
        """
        scores = {}
        
        # 1. 个人信息相关性评分
        scores['personal_relevance'] = self._score_personal_relevance(password)
        
        # 2. 模式常见度评分
        scores['pattern_commonality'] = self._score_pattern_commonality(password)
        
        # 3. 结构可能性评分
        scores['structural_likelihood'] = self._score_structural_likelihood(password)
        
        # 4. 复杂度平衡评分
        scores['complexity_balance'] = self._score_complexity_balance(password)
        
        # 5. 语言自然度评分
        scores['linguistic_naturalness'] = self._score_linguistic_naturalness(password)
        
        # 6. 时间相关性评分
        scores['temporal_relevance'] = self._score_temporal_relevance(password)
        
        # 7. 文化因素评分
        scores['cultural_factors'] = self._score_cultural_factors(password)
        
        # 加权总分
        total_score = sum(scores[k] * self.weights[k] for k in scores)
        
        # 额外的zxcvbn评估
        if ZXCVBN_AVAILABLE:
            user_inputs = list(self.user.variants['names']) + \
                         list(self.user.variants['numbers']) + \
                         list(self.user.variants['dates'])
            try:
                result = zxcvbn.zxcvbn(password, user_inputs=user_inputs[:20])
                # 适中难度的密码更可能
                if 1 <= result['score'] <= 3:
                    total_score += (4 - abs(result['score'] - 2)) * 0.5
            except:
                pass
        
        return total_score
    
    def _score_personal_relevance(self, password: str) -> float:
        """个人信息相关性评分"""
        score = 0.0
        pwd_lower = password.lower()
        
        # 检查各种个人信息变体
        for name_variant in self.user.variants['names']:
            if name_variant and len(name_variant) > 2:
                if name_variant in pwd_lower:
                    # 位置权重
                    if pwd_lower.startswith(name_variant):
                        score += 2.0
                    elif pwd_lower.endswith(name_variant):
                        score += 1.5
                    else:
                        score += 1.0
                    
                    # 完全匹配加分
                    if pwd_lower == name_variant:
                        score += 1.0
        
        # 数字相关性
        for number in self.user.variants['numbers']:
            if number in password:
                score += 1.5
                # 生日或电话号码特别加分
                if number == self.user.birth or number == self.user.phone:
                    score += 1.0
        
        # 日期相关性
        for date in self.user.variants['dates']:
            if date in password:
                score += 1.8
        
        # 组合相关性
        for combo in self.user.variants['combinations']:
            if combo in pwd_lower:
                score += 1.5
        
        # 首字母组合
        initials_str = ''.join(sorted(self.user.variants['initials']))
        if len(initials_str) >= 2 and initials_str in pwd_lower:
            score += 1.0
        
        return min(score, 10.0)  # 上限10分
    
    def _score_pattern_commonality(self, password: str) -> float:
        """模式常见度评分"""
        score = 0.0
        
        # 检查各类常见模式
        # 数字模式
        for pattern in self.pattern_analyzer.PATTERN_DATABASE['numeric_simple']:
            if re.match(pattern, password):
                score += 1.5
                break
        
        # 字母数字组合
        for pattern in self.pattern_analyzer.PATTERN_DATABASE['alphanumeric']:
            if re.match(pattern, password):
                score += 2.0
                break
        
        # 键盘模式
        pwd_lower = password.lower()
        for kbd_pattern in self.pattern_analyzer.PATTERN_DATABASE['keyboard']:
            if kbd_pattern in pwd_lower:
                score += 1.5
                break
        
        # 常见后缀
        for suffix in self.pattern_analyzer.PATTERN_DATABASE['common_suffixes']:
            if password.endswith(suffix):
                score += 1.8
                # 前缀是个人信息时额外加分
                prefix = password[:-len(suffix)]
                if prefix.lower() in self.user.variants['names']:
                    score += 2.0
                break
        
        # 常见前缀
        for prefix in self.pattern_analyzer.PATTERN_DATABASE['common_prefixes']:
            if pwd_lower.startswith(prefix):
                score += 1.0
                break
        
        # 特殊字符模式
        for pattern in self.pattern_analyzer.PATTERN_DATABASE['special_patterns']:
            if re.match(pattern, password):
                score += 1.2
                break
        
        return min(score, 8.0)
    
    def _score_structural_likelihood(self, password: str) -> float:
        """结构可能性评分"""
        structure = self.pattern_analyzer.analyze_structure(password)
        score = 0.0
        
        # 长度评分（8-12最常见）
        length = structure['length']
        if 8 <= length <= 10:
            score += 3.0
        elif 6 <= length <= 7 or 11 <= length <= 12:
            score += 2.0
        elif 13 <= length <= 16:
            score += 1.0
        elif length < 6 or length > 20:
            score -= 1.0
        
        # 字符类型组合（2-3种最常见）
        if structure['char_types'] == 2:
            score += 2.5
        elif structure['char_types'] == 3:
            score += 1.5
        elif structure['char_types'] == 1:
            score += 1.0
        
        # 首字母大写模式
        if structure['has_upper'] and structure['has_lower']:
            if password[0].isupper() and password[1:].islower():
                score += 1.0
        
        # 避免过度重复
        if not structure['has_repeat']:
            score += 0.5
        
        # 避免纯顺序
        if not structure['is_sequential']:
            score += 0.5
        
        return min(score, 8.0)
    
    def _score_complexity_balance(self, password: str) -> float:
        """复杂度平衡评分"""
        structure = self.pattern_analyzer.analyze_structure(password)
        score = 0.0
        
        # 熵值在合理范围（不太高也不太低）
        entropy = structure['entropy_estimate']
        if 25 <= entropy <= 45:
            score += 2.0
        elif 20 <= entropy < 25 or 45 < entropy <= 55:
            score += 1.0
        elif entropy < 15 or entropy > 70:
            score -= 0.5
        
        # 适度的特殊字符使用
        special_count = len(re.findall(r'[^a-zA-Z0-9]', password))
        if special_count == 1:
            score += 1.5
        elif special_count == 2:
            score += 1.0
        elif special_count > 3:
            score -= 0.5
        
        # 数字分布
        digits = re.findall(r'\d+', password)
        if digits:
            # 数字在末尾最常见
            if password[-1].isdigit():
                score += 1.0
            # 常见数字长度
            for d in digits:
                if len(d) in [2, 3, 4, 6, 8]:
                    score += 0.5
                    break
        
        return min(score, 6.0)
    
    def _score_linguistic_naturalness(self, password: str) -> float:
        """语言自然度评分"""
        score = 0.0
        pwd_lower = password.lower()
        
        # 元音辅音交替（更自然）
        has_vowels = bool(re.search(r'[aeiou]', pwd_lower))
        has_consonants = bool(re.search(r'[bcdfghjklmnpqrstvwxyz]', pwd_lower))
        
        if has_vowels and has_consonants:
            score += 1.0
            
            # 检查是否有合理的音节结构
            syllable_pattern = r'[bcdfghjklmnpqrstvwxyz]*[aeiou]+[bcdfghjklmnpqrstvwxyz]*'
            if re.search(syllable_pattern, pwd_lower):
                score += 1.0
        
        # 检查拼音模式
        for pinyin in self.pattern_analyzer.PATTERN_DATABASE['chinese_pinyin']:
            if pinyin in pwd_lower:
                score += 2.0
                break
        
        # 驼峰命名或下划线命名
        if re.match(r'^[a-z]+[A-Z][a-zA-Z]*$', password):  # camelCase
            score += 1.0
        elif '_' in password and password.count('_') <= 3:  # snake_case
            score += 1.0
        
        # 避免随机字符串特征
        # 连续辅音或元音不超过3个
        if not re.search(r'[bcdfghjklmnpqrstvwxyz]{4,}', pwd_lower) and \
           not re.search(r'[aeiou]{4,}', pwd_lower):
            score += 0.5
        
        return min(score, 5.0)
    
    def _score_temporal_relevance(self, password: str) -> float:
        """时间相关性评分"""
        score = 0.0
        
        # 当前年份相关
        current_year = datetime.now().year
        recent_years = [str(year) for year in range(current_year - 2, current_year + 2)]
        
        for year in recent_years:
            if year in password:
                score += 1.5
                break
            if year[-2:] in password:  # 年份后两位
                score += 1.0
                break
        
        # 常见年份（出生年代）
        birth_years = ['1970', '1980', '1985', '1988', '1989', '1990', '1991', '1992', 
                      '1993', '1994', '1995', '1996', '1997', '1998', '1999', '2000']
        for year in birth_years:
            if year in password or year[-2:] in password:
                score += 1.0
                break
        
        # 特殊日期
        special_dates = ['0101', '0214', '0520', '1111', '1212', '1225', '1314']
        for date in special_dates:
            if date in password:
                score += 1.2
                break
        
        return min(score, 4.0)
    
    def _score_cultural_factors(self, password: str) -> float:
        """文化因素评分"""
        score = 0.0
        pwd_lower = password.lower()
        
        # 幸运数字
        lucky_numbers = ['8', '88', '888', '8888', '6', '66', '666', '9', '99', '168']
        for num in lucky_numbers:
            if num in password:
                score += 1.0
                break
        
        # 特殊含义数字
        special_meanings = {
            '520': 1.5,  # 我爱你
            '521': 1.5,  # 我愿意
            '1314': 1.5,  # 一生一世
            '5201314': 2.0,  # 我爱你一生一世
            '7758': 1.0,  # 亲亲我吧
            '3344': 1.0,  # 生生世世
        }
        
        for pattern, weight in special_meanings.items():
            if pattern in password:
                score += weight
                break
        
        # 中东地区常见模式（考虑数据集特征）
        if any(name in ['AHMED', 'ALI', 'HASSAN', 'MOHAMED', 'KHALID'] 
               for name in self.user.name_parts):
            # 阿拉伯数字组合
            if re.search(r'(123|786|313)', password):
                score += 1.0
        
        return min(score, 4.0)

def create_ensemble_evaluator(user_profile: AdvancedUserProfile) -> callable:
    """创建集成评估器"""
    evaluator = AdvancedPasswordEvaluator(user_profile)
    
    def ensemble_evaluate(password: str) -> float:
        """集成评估函数"""
        # 主评估器得分
        main_score = evaluator.evaluate_password(password)
        
        # 快速规则加分/减分
        quick_adjustments = 0.0
        
        # 完全匹配账户名或邮箱用户名
        if password.lower() == user_profile.account.lower():
            quick_adjustments += 3.0
        
        # 简单变换
        for name in user_profile.name_parts:
            if name:
                # name123, name2023等
                if re.match(f'^{name.lower()}\\d{{2,4}}$', password.lower()):
                    quick_adjustments += 2.5
                # name@123, name#123等
                if re.match(f'^{name.lower()}[@#!$]\\d{{2,4}}$', password.lower()):
                    quick_adjustments += 2.0
        
        # 生日直接使用
        if user_profile.birth and password == user_profile.birth:
            quick_adjustments += 2.0
        
        # 电话号码直接使用
        if user_profile.phone and password == user_profile.phone:
            quick_adjustments += 1.5
        
        return main_score + quick_adjustments
    
    return ensemble_evaluate

def process_passwords_advanced(dataset_path: str, answer_dir: str):
    """高级处理主函数"""
    print("="*60)
    print("口令安全研究 - 高级密码评估系统")
    print("="*60)
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 读取数据集
    print("\n[步骤 1/5] 载入身份信息数据集...")
    users = []
    
    try:
        with open(dataset_path, 'r', encoding='utf-8', errors='ignore') as f:
            for idx, line in enumerate(f):
                if line.strip():
                    users.append(AdvancedUserProfile(line, idx))
    except Exception as e:
        print(f"错误: 读取数据集失败: {e}")
        sys.exit(1)
    
    print(f"✓ 成功载入 {len(users)} 个用户档案")
    
    # 读取answer文件
    print("\n[步骤 2/5] 扫描密码候选集...")
    answer_files = []
    
    for filename in os.listdir(answer_dir):
        if filename.startswith('answer') and filename.endswith('.txt'):
            if filename != 'answer_final.txt':  # 排除输出文件
                answer_files.append(os.path.join(answer_dir, filename))
    
    print(f"✓ 发现 {len(answer_files)} 个密码候选文件")
    
    # 读取所有密码
    print("\n[步骤 3/5] 加载和预处理密码集合...")
    all_user_passwords = [set() for _ in range(len(users))]
    
    for answer_file in tqdm(answer_files, desc="读取文件"):
        try:
            with open(answer_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            user_blocks = content.split('<END>')
            for user_idx in range(min(len(user_blocks), len(users))):
                block = user_blocks[user_idx].strip()
                if block:
                    passwords = [line.strip() for line in block.split('\n') 
                               if line.strip() and not line.startswith('#')]
                    all_user_passwords[user_idx].update(passwords)
        
        except Exception as e:
            print(f"警告: 处理文件 {answer_file} 时出错: {e}")
    
    # 统计
    total_unique = sum(len(pwd_set) for pwd_set in all_user_passwords)
    print(f"✓ 共加载 {total_unique} 个唯一密码")
    
    # 评估和排序
    print("\n[步骤 4/5] 智能评估和优化排序...")
    final_results = []
    
    with tqdm(total=len(users), desc="评估进度") as pbar:
        for user_idx, user in enumerate(users):
            passwords = all_user_passwords[user_idx]
            
            if passwords:
                # 创建集成评估器
                evaluator = create_ensemble_evaluator(user)
                
                # 评估所有密码
                scored_passwords = []
                for pwd in passwords:
                    try:
                        score = evaluator(pwd)
                        scored_passwords.append((pwd, score))
                    except Exception as e:
                        # 如果评估失败，给予默认分数
                        scored_passwords.append((pwd, 0.0))
                
                # 排序并选择前10000个
                scored_passwords.sort(key=lambda x: x[1], reverse=True)
                top_passwords = [pwd for pwd, score in scored_passwords[:10000]]
                
                # 二次优化：确保多样性
                if len(top_passwords) > 100:
                    # 保留前100个最高分的
                    final_passwords = top_passwords[:100]
                    # 剩余的按一定间隔采样，保持多样性
                    remaining = top_passwords[100:]
                    step = max(1, len(remaining) // 9900)
                    final_passwords.extend(remaining[::step][:9900])
                    final_results.append(final_passwords)
                else:
                    final_results.append(top_passwords)
            else:
                final_results.append([])
            
            pbar.update(1)
    
    # 写入结果
    print("\n[步骤 5/5] 生成最终答案文件...")
    output_file = os.path.join(answer_dir, 'answer_final.txt')
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for user_idx, passwords in enumerate(final_results):
            for pwd in passwords:
                f.write(pwd + '\n')
            
            if user_idx < len(final_results) - 1:
                f.write('<END>\n')
    
    # 最终统计
    print("\n" + "="*60)
    print("处理完成！统计信息：")
    print("="*60)
    print(f"  处理用户数: {len(users)}")
    print(f"  输出文件: {output_file}")
    print(f"  平均每用户密码数: {sum(len(p) for p in final_results) / len(users):.1f}")
    print(f"  总密码数: {sum(len(p) for p in final_results)}")
    
    # 质量指标
    non_empty = sum(1 for p in final_results if len(p) > 0)
    print(f"  有效用户数: {non_empty}/{len(users)} ({100*non_empty/len(users):.1f}%)")
    
    print("="*60)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='口令安全研究 - 高级密码评估系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python process_advanced.py ./在线数据集.txt ./answers

该工具使用多维度评分系统对密码进行智能评估和排序。
        """
    )
    
    parser.add_argument('dataset', help='身份信息数据集文件路径')
    parser.add_argument('answer_dir', help='包含answer*.txt文件的目录')
    parser.add_argument('--verbose', '-v', action='store_true', 
                      help='显示详细输出')
    
    args = parser.parse_args()
    
    # 验证路径
    if not os.path.exists(args.dataset):
        print(f"错误: 数据集文件不存在: {args.dataset}")
        sys.exit(1)
    
    if not os.path.isdir(args.answer_dir):
        print(f"错误: 答案目录不存在: {args.answer_dir}")
        sys.exit(1)
    
    # 执行处理
    process_passwords_advanced(args.dataset, args.answer_dir)

if __name__ == '__main__':
    main()
