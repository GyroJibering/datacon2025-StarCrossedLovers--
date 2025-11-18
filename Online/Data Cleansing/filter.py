import csv
import os
import argparse
import re
from difflib import SequenceMatcher
from functools import lru_cache

# 预编译正则表达式
NORMALIZE_PATTERN = re.compile(r'[^a-zA-Z0-9]')
DIGIT_PATTERN = re.compile(r'\D')

@lru_cache(maxsize=10000)
def normalize_text(text):
    """标准化文本：小写、移除常见分隔符和特殊字符（带缓存）"""
    if not text:
        return ""
    return NORMALIZE_PATTERN.sub('', text.lower())

@lru_cache(maxsize=1000)
def extract_birthday_components(birthday):
    """提取生日的各种可能组合（带缓存）"""
    if not birthday:
        return tuple()
    
    # 清理生日，只保留数字
    birthday_clean = DIGIT_PATTERN.sub('', birthday)
    
    if len(birthday_clean) != 8:
        return tuple()
    
    year = birthday_clean[:4]
    month = birthday_clean[4:6]
    day = birthday_clean[6:8]
    year_short = birthday_clean[2:4]
    
    # 生成各种可能的生日组合
    combinations = [
        year,           # 1969
        year_short,     # 69
        month,          # 02
        day,            # 04
        month + day,    # 0204
        day + month,    # 0402
        year_short + month,      # 6902
        year_short + day,        # 6904
        month + year_short,      # 0269
        day + year_short,        # 0469
        year_short + month + day, # 690204
        month + day + year_short, # 020469
        day + month + year_short, # 040269
    ]
    
    return tuple(comp for comp in combinations if comp and len(comp) >= 2)

@lru_cache(maxsize=1000)
def extract_phone_components(phone):
    """提取电话号码的各种可能组合（带缓存）"""
    if not phone:
        return tuple()
    
    # 清理电话号码，只保留数字
    phone_clean = DIGIT_PATTERN.sub('', phone)
    
    if len(phone_clean) < 4:
        return tuple()
    
    components = []
    
    # 完整电话号码
    if len(phone_clean) >= 6:
        components.append(phone_clean)
    
    # 后4位
    if len(phone_clean) >= 4:
        components.append(phone_clean[-4:])
    
    # 后6位
    if len(phone_clean) >= 6:
        components.append(phone_clean[-6:])
    
    # 后8位
    if len(phone_clean) >= 8:
        components.append(phone_clean[-8:])
    
    # 前3位（区号）
    if len(phone_clean) >= 3:
        components.append(phone_clean[:3])
    
    # 中间部分（去掉前3位和后4位）
    if len(phone_clean) >= 10:
        components.append(phone_clean[3:-4])
    
    return tuple(set(components))

@lru_cache(maxsize=1000)
def calculate_similarity(str1, str2):
    """计算两个字符串的相似度（带缓存）"""
    if not str1 or not str2:
        return 0
    return SequenceMatcher(None, str1, str2).ratio()

@lru_cache(maxsize=1000)
def extract_name_variants(name):
    """提取姓名的各种变体（带缓存）"""
    if not name:
        return tuple()
    
    variants = []
    name_clean = normalize_text(name)
    
    # 按 空格 分割姓名
    name_parts = name.strip().split(' ')
    
    for part in name_parts:
        part_clean = normalize_text(part)
        if len(part_clean) >= 3:  # 只考虑长度>=3的部分
            variants.append(part_clean)
    
    # 添加完整姓名（去除空格）
    if len(name_clean) >= 3:
        variants.append(name_clean)
    
    # 添加首字母组合
    if len(name_parts) >= 2:
        initials = ''.join([normalize_text(part)[:1] for part in name_parts if normalize_text(part)])
        if len(initials) >= 2:
            variants.append(initials)
    
    return tuple(set(variants))

def check_password_relationship(fields):
    """检查密码与用户信息的关联关系"""
    if len(fields) < 4:
        return False
    
    # 解析字段 - 正确处理可能的字段顺序
    email = fields[0].strip() if len(fields) > 0 else ""
    password = fields[1].strip() if len(fields) > 1 else ""
    username = fields[2].strip() if len(fields) > 2 else ""
    display_name = fields[3].strip() if len(fields) > 3 else ""
    
    # 检测第5和第6个字段，判断哪个是电话号码，哪个是生日
    phone = ""
    birthday = ""
    
    if len(fields) >= 5:
        field4 = fields[4].strip()
        field5 = fields[5].strip() if len(fields) >= 6 else ""
        
        # 判断哪个字段是生日（8位数字）哪个是电话号码
        field4_digits = DIGIT_PATTERN.sub('', field4)
        field5_digits = DIGIT_PATTERN.sub('', field5)
        
        if len(field4_digits) == 8 and (not field5_digits or len(field5_digits) != 8):
            # field4是生日，field5是电话或空
            birthday = field4
            phone = field5
        elif len(field5_digits) == 8:
            # field5是生日，field4是电话
            phone = field4
            birthday = field5
        else:
            # 都不是8位数字，按长度判断
            if len(field4_digits) >= len(field5_digits):
                phone = field4
                birthday = field5
            else:
                phone = field5
                birthday = field4
    elif len(fields) == 5:
        # 只有一个额外字段，判断是电话还是生日
        field4 = fields[4].strip()
        field4_digits = DIGIT_PATTERN.sub('', field4)
        if len(field4_digits) == 8:
            birthday = field4
        else:
            phone = field4
    
    if not password:
        return False
    
    password_norm = normalize_text(password)
    password_lower = password.lower()
    
    # 提取邮箱用户名
    email_username = ""
    if '@' in email:
        email_username = normalize_text(email.split('@')[0])
    
    # 提取各种用户信息变体（使用缓存）
    username_variants = extract_name_variants(username)
    display_name_variants = extract_name_variants(display_name)
    birthday_components = extract_birthday_components(birthday)
    phone_components = extract_phone_components(phone)
    
    # 合并所有变体并转换为集合以提高查找速度
    all_variants = [email_username] + list(username_variants) + list(display_name_variants)
    all_variants = [v for v in all_variants if v]  # 过滤空值
    all_variants_set = set(all_variants)
    
    # 规则1: 完全匹配或高相似度匹配
    if password_norm in all_variants_set:
        return True
    
    # 高相似度匹配 - 只对长度>=4的变体检查
    long_variants = [v for v in all_variants if len(v) >= 4]
    for variant in long_variants:
        similarity = calculate_similarity(variant, password_norm)
        if similarity >= 0.8:
            return True
    
    # 规则2: 子字符串包含关系
    for variant in all_variants:
        if len(variant) < 3:
            continue
        
        # 密码包含用户信息
        if len(variant) >= 4 and variant in password_norm:
            return True
        
        # 用户信息包含密码（且长度相近）
        if password_norm in variant and abs(len(password_norm) - len(variant)) <= 3:
            return True
    
    # 规则3: 生日相关匹配
    for birthday_comp in birthday_components:
        if birthday_comp in password_norm:
            return True
    
    # 规则4: 电话号码相关匹配
    for phone_comp in phone_components:
        if phone_comp in password_norm:
            return True
        # 检查密码是否完全是电话号码的一部分
        if password_norm.isdigit() and password_norm in phone_comp:
            return True
    
    # 规则5: 组合匹配（用户名+生日、用户名+电话等）
    # 预计算所有组合以避免重复计算
    combos = set()
    for variant in all_variants:
        if len(variant) >= 3:
            # 与生日组合
            for birthday_comp in birthday_components:
                combos.add(variant + birthday_comp)
                combos.add(birthday_comp + variant)
            
            # 与电话组合
            for phone_comp in phone_components:
                if len(phone_comp) >= 3:
                    combos.add(variant + phone_comp)
                    combos.add(phone_comp + variant)
    
    # 检查完全匹配
    if password_norm in combos:
        return True
    
    # 检查包含关系
    for combo in combos:
        if (combo in password_norm or password_norm in combo) and abs(len(password_norm) - len(combo)) <= 2:
            return True
    
    # 规则6: 数字替换和变体匹配
    # 预处理替换字符串以避免重复计算
    password_replaced = password_lower.replace('0', 'o').replace('3', 'e').replace('@', 'a').replace('1', 'i')
    
    for variant in all_variants:
        if len(variant) >= 3:
            variant_replaced = variant.replace('0', 'o').replace('3', 'e').replace('@', 'a').replace('1', 'i')
            if calculate_similarity(password_replaced, variant_replaced) >= 0.8:
                return True
    
    # 规则7: 重复模式匹配
    # 预编译正则表达式模式
    for variant in all_variants:
        if len(variant) >= 3:
            # 检查重复模式，如 "red6969red"
            pattern = re.escape(variant)
            if re.search(f'{pattern}.*{pattern}', password_lower):
                return True
    
    # 规则8: 纯数字密码与电话号码/生日的特殊匹配
    if password_norm.isdigit() and len(password_norm) >= 4:
        # 与电话号码后缀匹配
        for phone_comp in phone_components:
            if password_norm == phone_comp or phone_comp.endswith(password_norm):
                return True
        
        # 与生日组件匹配
        for birthday_comp in birthday_components:
            if password_norm == birthday_comp:
                return True
    
    return False

def process_csv_file(input_file, output_file=None):
    """处理CSV文件，筛选出有关联的记录"""
    if not os.path.exists(input_file):
        print(f"错误: 文件 '{input_file}' 不存在")
        return
    
    if not output_file:
        name, ext = os.path.splitext(input_file)
        output_file = f"{name}_filtered{ext}"
    
    related_records = []
    total_records = 0
    
    try:
        # 批量读取文件
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 检测分隔符
        if '\t' in content:
            delimiter = '\t'
        else:
            delimiter = ','
        
        # 分割行并处理
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            # 手动分割以避免CSV模块开销
            if delimiter == '\t':
                row = line.split('\t')
            else:
                row = line.split(',')
            
            if len(row) < 4:
                continue
            
            total_records += 1
            
            # 每处理1000行显示进度
            if total_records % 1000 == 0:
                print(f"已处理 {total_records} 行...")
            
            is_related = check_password_relationship(row)
            
            if is_related:
                related_records.append(line)  # 直接保存原始行
    
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return
    
    # 批量写入结果
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in related_records:
                f.write(record + '\n')
        
        print(f"处理完成!")
        print(f"总记录数: {total_records}")
        print(f"发现关联记录: {len(related_records)}")
        print(f"关联率: {len(related_records)/total_records*100:.1f}%")
        print(f"结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"写入文件时出错: {e}")


def parse_arguments():
    """
    解析命令行参数。
    """
    parser = argparse.ArgumentParser(
        description='处理单个 CSV 文件，执行数据分析或转换功能。'
    )
    # 定义命令行参数
    parser.add_argument(
        'input_file', 
        type=str, 
        help='要处理的 CSV 文件路径。'
    )
    return parser.parse_args()


# 核心执行块，使用命令行参数
if __name__ == "__main__":
    args = parse_arguments()
    
    # 获取用户输入的 CSV 文件路径
    input_file = '../' + args.input_file
    
    print(f"开始分析文件: {input_file}")
    
    # 调用您的 CSV 处理函数
    process_csv_file(input_file)
