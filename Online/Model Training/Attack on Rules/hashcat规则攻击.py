#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os

class PasswordGuesser:
    def __init__(self, max_guesses=10000, rule_file='Unicorn3k.rule'):
        self.max_guesses = max_guesses
        self.hashcat_rules = self.load_hashcat_rules(rule_file)
        if self.hashcat_rules:
            print(f"成功加载 {len(self.hashcat_rules)} 条来自 {rule_file} 的规则。")
        else:
            print(f"警告: 未能从 {rule_file} 加载任何规则。请检查文件是否存在且内容正确。")

    # ====================== HASHCAT 规则引擎 (V2) ======================
    def load_hashcat_rules(self, rule_file):
        """加载 Hashcat 规则文件，忽略注释和空行。"""
        if not os.path.exists(rule_file):
            return []
        rules = []
        try:
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        rules.append(line)
        except Exception as e:
            print(f"读取规则文件时出错: {e}")
        return rules

    def apply_hashcat_rule(self, word, rule):
        """将 Hashcat 规则字符串应用于单词，支持空格分隔的多指令。"""
        if not word:
            return ""
        
        output = list(word)
        
        # 将规则按空格分割成多个部分，每个部分是一个指令
        parts = rule.split()
        
        for part in parts:
            if not part: continue
            
            cmd = part[0]
            arg = part[1:]
            
            # 简单指令 (无参数)
            if cmd == ':': pass
            elif cmd == 'l': output = [c.lower() for c in output]
            elif cmd == 'u': output = [c.upper() for c in output]
            elif cmd == 'c':
                if output:
                    output = [c.lower() for c in output]
                    output[0] = output[0].upper()
            elif cmd == 'C':
                if output:
                    output = [c.upper() for c in output]
                    output[0] = output[0].lower()
            elif cmd == 't':
                output = [c.upper() if c.islower() else c.lower() for c in output]
            elif cmd == 'r': output.reverse()
            elif cmd == '[':
                if output: output.pop(0)
            elif cmd == ']':
                if output: output.pop()
            
            # 带参数指令
            elif cmd == '$': # Append char
                if arg: output.append(arg[0])
            elif cmd == '^': # Prepend char
                if arg: output.insert(0, arg[0])
            elif cmd == 'T': # Toggle case at pos
                try:
                    pos = int(arg[0], 16)
                    if pos < len(output):
                        output[pos] = output[pos].upper() if output[pos].islower() else output[pos].lower()
                except (ValueError, IndexError): pass
            elif cmd == 'D': # Duplicate char at pos (JtR-style)
                try:
                    # 'D2' means duplicate the 2nd char (index 1)
                    pos = int(arg[0]) - 1 
                    if 0 <= pos < len(output):
                        output.insert(pos + 1, output[pos])
                except (ValueError, IndexError): pass
            elif cmd == '+': # Append char (common alternative syntax)
                if arg: output.append(arg[0])
            elif cmd == '-': # Prepend char (common alternative syntax)
                if arg: output.insert(0, arg[0])

        return "".join(output)

    # ====================== 解析用户信息 ======================
    def parse_user_info(self, line):
        user_info = { 'email': '', 'names': [], 'account': '', 'phone': '', 'birth': '' }
        for field in line.split('\t'):
            if ':' not in field: continue
            k, v = field.split(':', 1)
            k, v = k.strip(), v.strip()
            if k == 'email' and v: user_info['email'] = v
            elif k == 'name' and v: user_info['names'] = [n.strip() for n in v.split('|') if n.strip()]
            elif k == 'account' and v: user_info['account'] = v
            elif k == 'phone' and v: user_info['phone'] = v
            elif k == 'birth' and v: user_info['birth'] = v
        return user_info

    # ====================== 变体提取 ======================
    def extract_name_variants(self, names):
        variants = []
        if not names: return variants
        for name in names:
            if not name: continue
            variants.extend([name.lower(), name.capitalize(), name.title()])
            if ' ' in name:
                parts = name.split()
                if len(parts) > 1:
                    fname, lname = parts[0], parts[-1]
                    variants.extend([
                        fname.lower() + lname.lower(),
                        fname.capitalize() + lname.capitalize(),
                        fname.lower() + lname.capitalize(),
                        fname[0].lower() + lname.lower(),
                    ])
        return list(set(variants))

    def extract_date_variants(self, birth):
        variants = []
        if not birth: return variants
        d = re.sub(r'[^0-9]', '', birth)
        if len(d) == 8 and 1950 <= int(d[:4]) <= 2020:
            y, m, day = d[:4], d[4:6], d[6:]
            yy = y[2:]
            variants.extend([y, yy, m + day, d, yy + m + day])
        return variants

    def extract_phone_variants(self, phone):
        if not phone: return []
        digits = re.sub(r'[^0-9]', '', phone)
        if len(digits) >= 4: return [digits[-4:], digits]
        return []

    def extract_email_variants(self, email):
        if email and '@' in email:
            u = email.split('@')[0]
            if len(u) > 2: return [u, u.lower(), u.capitalize()]
        return []

    # ====================== 组合生成 ======================
    def generate_combined_passwords(self, info):
        cand = []
        name_v = info['name_variants']
        date_v = info['date_variants']
        phone_v = info['phone_variants']
        email_v = info['email_variants']
        acct = info['account'].lower() if info['account'] else ''

        # 1. 基础词汇：将所有提取的变体作为基础
        base_words = list(set(name_v + date_v + phone_v + email_v + ([acct] if acct else [])))
        cand.extend(base_words)
        
        # 2. 基础组合
        for n in name_v:
            for d in date_v: cand.extend([n + d, d + n])
            for p in phone_v: cand.extend([n + p[-4:]] if len(p)>=4 else [])

        # 3. 添加常用后缀
        for base in (name_v + ([acct] if acct else [])):
            for suffix in ['123', '!', '@123', '1', '2023', '2024']:
                cand.append(base + suffix)
        
        cand.extend(['password', '123456', '123456789', 'qwerty'])

        # 4. *** 应用 Unicorn3k.rule 规则 ***
        if self.hashcat_rules:
            # 选择高质量的基础词来应用规则
            # 账号名、邮箱名、最简短的名字变体 通常是最好的基础
            base_words_for_rules = sorted(list(set(email_v + name_v + ([acct] if acct else []))), key=len)[:10]
            
            for base in base_words_for_rules:
                if base and len(base) > 3: # 避免对太短的词应用规则
                    for rule in self.hashcat_rules:
                        mutated = self.apply_hashcat_rule(base, rule)
                        if mutated and mutated != base:
                            cand.append(mutated)
        
        return cand

    # ====================== 单用户猜测（保持顺序） ======================
    def generate_guesses(self, user_info):
        info = {
            'name_variants': self.extract_name_variants(user_info['names']),
            'date_variants': self.extract_date_variants(user_info['birth']),
            'phone_variants': self.extract_phone_variants(user_info['phone']),
            'email_variants': self.extract_email_variants(user_info['email']),
            'account': user_info['account'],
        }
        cands = self.generate_combined_passwords(info)

        # 有序去重 + 长度过滤
        seen = set()
        uniq = []
        for p in cands:
            if p and 6 <= len(p) <= 20 and p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq[:self.max_guesses]

    # ====================== 批量处理 ======================
    def process_targets(self, input_file, output_file):
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]

        results = []
        for idx, line in enumerate(lines, 1):
            print(f"处理用户 {idx}/{len(lines)}...", end='\r')
            info = self.parse_user_info(line)
            guesses = self.generate_guesses(info)
            results.append(guesses)

        with open(output_file, 'w', encoding='utf-8') as out:
            for i, guesses in enumerate(results):
                out.write('\n'.join(guesses) + '\n')
                if i < len(results) - 1:
                    out.write('<END>\n')
        print(f"\n完成！共 {len(results)} 个用户，结果已写入 {output_file}")

# ====================== 主入口 ======================
def main():
    # 初始化时会自动加载 Unicorn3k.rule
    guesser = PasswordGuesser(max_guesses=10000, rule_file='Unicorn3k.rule')
    guesser.process_targets('targets.txt', 'answer.txt')

if __name__ == '__main__':
    main()