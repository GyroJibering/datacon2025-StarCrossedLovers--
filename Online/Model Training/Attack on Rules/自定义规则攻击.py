#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

class PasswordGuesser:
    def __init__(self, max_guesses=10000):
        self.max_guesses = max_guesses

    # ====================== 解析用户信息 ======================
    def parse_user_info(self, line):
        user_info = {
            'email': '',
            'names': [],
            'account': '',
            'phone': '',
            'birth': ''
        }
        for field in line.split('\t'):
            if ':' not in field:
                continue
            k, v = field.split(':', 1)
            k, v = k.strip(), v.strip()
            if k == 'email' and v:
                user_info['email'] = v
            elif k == 'name' and v:
                user_info['names'] = [n.strip() for n in v.split('|') if n.strip()]
            elif k == 'account' and v:
                user_info['account'] = v
            elif k == 'phone' and v:
                user_info['phone'] = v
            elif k == 'birth' and v:
                user_info['birth'] = v
        return user_info

    # ====================== 变体提取 ======================
    def extract_name_variants(self, names):
        variants = []
        if not names:
            return variants
        for name in names:
            if not name:
                continue
            lower = name.lower()
            upper = name.upper()
            cap = name.capitalize()
            title = name.title()
            variants.extend([lower, upper, cap, title])
            variants.append(lower[::-1])
            variants.append(cap[::-1])
            if ' ' in name:
                parts = name.split()
                for p in parts:
                    variants.extend(self.extract_name_variants([p]))
            if len(name) > 1:
                variants.append(name[0].upper() + name[1:].lower())
                variants.append(name[0].lower() + name[1:])
        if len(names) > 1:
            full = ''.join(names)
            variants.append(full.lower())
            variants.append(full.upper())
            variants.append(full.capitalize())
            first_last = names[0] + names[-1]
            variants.append(first_last.lower())
            variants.append(first_last.capitalize())
            if names[0]:
                initial_last = names[0][0].upper() + names[-1].lower()
                variants.extend([initial_last, initial_last.lower(), initial_last.upper()])
            if names[-1]:
                last_initial = names[-1].lower() + names[0][0].upper()
                variants.extend([last_initial, last_initial.capitalize()])
            fname = names[0].lower()
            lname = names[-1].lower()
            variants.extend([fname + lname[0], lname + fname[0], fname[0] + lname])
        return list(set(variants))  # 提前去重

    def extract_date_variants(self, birth):
        variants = []
        if not birth:
            return variants
        d = re.sub(r'[^0-9]', '', birth)
        if len(d) == 8 and 1950 <= int(d[:4]) <= 2010:
            y, m, day = d[:4], d[4:6], d[6:]
            yy = y[2:]
            variants.extend([y, yy, m + day, day + m, d, f"{y}-{m}-{day}", f"{y}/{m}/{day}", f"{m}/{day}/{yy}"])
            variants.extend([m + day + yy, day + m + yy, yy + m + day, f"{y}.{m}.{day}", f"{m}.{day}.{y}", f"{day}-{m}-{y}"])
            variants.extend([f"{day}/{m}/{y}", f"{day}.{m}.{yy}", y + m, y + day, yy + day])
        elif len(d) == 4 and 1950 <= int(d) <= 2010:
            variants.extend([d, d[2:]])
        return variants

    def extract_phone_variants(self, phone):
        variants = []
        if not phone:
            return variants
        digits = re.sub(r'[^0-9]', '', phone)
        if len(digits) >= 4:
            variants.extend([digits[-4:], digits[-6:] if len(digits)>=6 else '', digits])
            variants.extend([digits[:4], digits[:6] if len(digits)>=6 else ''])
            if len(digits) > 7:
                variants.extend([digits[3:7], digits[-7:], digits[4:8]])
        return [v for v in variants if v]  # 过滤空字符串

    def extract_email_variants(self, email):
        variants = []
        if email and '@' in email:
            u = email.split('@')[0]
            domain = email.split('@')[1].split('.')[0]
            if len(u) > 2:
                variants.extend([u, u.lower(), u.upper(), u.capitalize()])
                u_no_num = re.sub(r'[0-9]', '', u).strip('.')
                if u_no_num != u and len(u_no_num)>1:
                    variants.extend([u_no_num.lower(), u_no_num.capitalize()])
                if len(domain)>2:
                    variants.append(domain.lower())
                    variants.append(domain.capitalize())
        return variants

    # ====================== 组合生成 ======================
    def generate_combined_passwords(self, info):
        cand = []
        name_v = info['name_variants']
        date_v = info['date_variants']
        phone_v = info['phone_variants']
        email_v = info['email_variants']
        acct = info['account'].lower() if info['account'] else ''

        # 1. 直接变体
        cand.extend(name_v + date_v + phone_v + email_v)
        if acct:
            cand.extend([acct, acct.capitalize(), acct.upper()])

        # 2. 超大数字后缀集（英文用户最爱）
        suffixes = ['', '1','2','3','4','5','6','7','8','9','0',
                    '01','12','13','21','23','69','88','99','007','123','1234','420','911',
                    '000','111','222','333','444','555','666','777','888','999',
                    '0000','1111','12345','123456','654321','777777','666666','888888',
                    '1980','1981','1982','1983','1984','1985','1986','1987','1988','1989',
                    '1990','1991','1992','1993','1994','1995','1996','1997','1998','1999',
                    '2000','2001','2002','2003','2004','2005','2006','2007','2008','2009','2010',
                    '2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025']
        for base in name_v + ([acct] if acct else []):
            for s in suffixes:
                if s:  # 避免空字符串重复
                    cand.extend([base + s, base.capitalize() + s, s + base, s + base.capitalize()])

        # 3. 特殊字符超丰富
        specials = ['!','@','#','$','%','^','&','*','_','-','+','=','?','.',
                    '!!','@@','##','$$','..','?!','!?','123!','@123','!@#','#_#','$$$']
        for base in name_v + ([acct] if acct else []):
            for s in specials:
                cand.extend([base + s, base.capitalize() + s, s + base, s + base.capitalize()])

        # 4. 名字+日期/电话/邮箱 全组合
        for n in name_v:
            for d in date_v:
                cand.extend([n+d, n+d[2:] if len(d)>2 else n+d, d+n, d[2:]+n if len(d)>2 else d+n, n.capitalize()+d, d+n.capitalize()])
            for p in phone_v:
                if len(p) >= 4:
                    cand.extend([n+p[-4:], p[-4:]+n, n+p[:4], p[:4]+n])
            for e in email_v:
                cand.extend([n+e, e+n])

        if acct:
            for d in date_v:
                cand.extend([acct+d, acct+d[2:] if len(d)>2 else acct+d, d+acct, acct.capitalize()+d])
            for p in phone_v:
                if len(p) >= 4:
                    cand.extend([acct+p[-4:], p[-4:]+acct])

        # 5. 顶级常见英文密码（2025最新泄露库统计）
        common = [
            'password','password1','Password','Password1','PASSWORD','123456','123456789','12345678',
            'qwerty','qwerty123','abc123','password123','admin','letmein','welcome','monkey','jesus',
            'sunshine','princess','flower','iloveyou','iloveyou1','football','baseball','soccer','hockey',
            'michael','jennifer','jordan','harley','ranger','buster','batman','superman','spiderman',
            'trustno1','ninja','shadow','master','killer','dragon','hunter','ginger','mustang','summer',
            'winter','spring','autumn','passw0rd','P@ssw0rd','Password123','password!','admin123','root',
            '1q2w3e4r','1qaz2wsx','qazwsx','zaq1zaq1','letmein1','welcome1','whatever','testing','login',
            'solo','starwars','hello','freedom','abc123','nicole','daniel','babygirl','hannah','destiny',
            'austin','andrew','tigger','pooh','sunshine1','princess1','corvette','mustang','cameron','mercedes'
        ]
        cand.extend(common)

        # 6. 超级LeetSpeak（修复版：使用 dict 方式，完全避免转义问题）
        leet1 = str.maketrans('lLoOsSaAiIeEtTbBgG','110055@@!!33778899')
        leet2 = str.maketrans({
            'c': '(', 'C': '(',
            'k': '|<', 'K': '|<',
            'p': '|>', 'P': '|>',
            'r': '|2', 'R': '|2',
            'v': '\\/', 'V': '\\/',
            'z': '2', 'Z': '2',
        })
        leet3 = {'a':'@', 's':'$', 'i':'!', 'e':'3', 'o':'0', 't':'7', 'g':'9'}

        def apply_leet(w):
            if not w:
                return []
            w1 = w.translate(leet1)
            w2 = w1.translate(leet2)
            w3 = ''.join(leet3.get(c.lower(), c) for c in w2)
            res = []
            if w1 != w: res.append(w1)
            if w2 != w1: res.append(w2)
            if w3 != w2.lower(): 
                res.append(w3)
                res.append(w3.title())
                res.append(w3.upper())
            return res
        
        for n in name_v + common[:50]:
            cand.extend(apply_leet(n))
            for s in ['1','!','123','@']:
                cand.extend(apply_leet(n + s))

        # 7. 重复模式
        for n in name_v[:15]:
            cand.extend([n*2, n*3, n.lower()*2])

        # 8. 英文常见词 + 名字
        eng_words = ['love','baby','girl','boy','sexy','hot','cool','king','queen','boss','god','jesus',
                     'angel','devil','star','rock','metal','punk','cat','dog','wolf','tiger','eagle','red',
                     'blue','green','black','white','gold','silver','diamond','money','cash','rich','life']
        for n in name_v[:20]:
            for w in eng_words:
                cand.extend([n+w, n+w.capitalize(), w+n, w.capitalize()+n, n.lower()+w])

        # 9. 键盘行走模式
        keyboard_patterns = [
            'qwerty','qwertyuiop','asdfghjkl','zxcvbnm','qazwsx','wsxedc','1q2w3e','2w3e4r',
            '1qaz','2wsx','3edc','4rfv','5tgb','6yhn','7ujm','8ik,','9ol.','0p;/'
        ]
        for n in name_v[:8]:
            for pat in keyboard_patterns:
                cand.extend([n+pat, pat+n, n+pat.capitalize()])

        # 10. 运动/品牌/游戏
        brands = ['nike','adidas','jordan','coke','pepsi','apple','google','facebook','twitter','instagram',
                  'netflix','youtube','ford','chevy','dodge','harley','marvel','starwars','pokemon','minecraft']
        for n in name_v[:10]:
            for b in brands:
                cand.extend([n+b.capitalize(), b.capitalize()+n])

        # 11. 月份 + 季节 + 星座
        months = ['january','february','march','april','may','june','july','august','september','october','november','december',
                  'jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec']
        if date_v:
            m_str = next((x for x in date_v if len(x)>=2 and x[:2] in [f'{i:02d}' for i in range(1,13)]), None)
            if m_str:
                m_num = int(m_str[:2])
                month_full = months[m_num-1]
                month_short = months[m_num+11]
                cand.extend([month_full, month_full.capitalize(), month_short, month_short.capitalize()])
                for n in name_v[:5]:
                    cand.extend([n+month_full.capitalize(), n+month_short.capitalize()])

        # 12. 美国州缩写
        states = ['ca','ny','tx','fl','il','pa','oh','ga','nc','mi','nj','va','wa','az','ma','in','tn','mo','md','wi']
        for n in name_v[:5]:
            for st in states:
                cand.extend([n+st.upper(), st.upper()+n])

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
            if p and len(p) >= 6 and p not in seen:
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
    guesser = PasswordGuesser(max_guesses=10000)
    guesser.process_targets('targets.txt', 'answer.txt')

if __name__ == '__main__':
    main()