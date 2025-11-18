import os

# --- 配置区 ---
# !!! 非常重要：这里的数字必须和你运行 targuess1_guess.exe 时 config.ini 中的 'maximum_guess_num' 设置完全一致！
# 默认是 10000。如果你的配置不同，请修改这里。
GUESSES_PER_USER = 10000

# 输入文件（来自C++程序，GBK编码，可能带有概率）
input_filename = 'combine_guess.txt'

# 用于确定用户数量的个人信息文件
targets_filename = 'targets.txt'

# 最终输出的文件（UTF-8编码，纯密码）
output_filename = 'combine_answer.txt'
# --- 配置区结束 ---

def reformat_guesses_from_file(input_path, targets_path, guesses_per_user, output_path):
    """
    读取一个连续的密码猜测文件，去除概率部分，根据用户数量和每个用户的猜测数，
    插入 <END> 分隔符，并以 UTF-8 编码保存。

    Args:
        input_path (str): C++程序生成的原始输出文件路径 (GBK/GB2312 编码)。
        targets_path (str): 包含目标用户信息的文件，用于计数。
        guesses_per_user (int): 每个用户生成的猜测密码数量。
        output_path (str): 格式化后要保存的文件路径 (UTF-8 编码)。
    """
    print("开始处理...")

    # 1. 检查输入文件是否存在
    if not os.path.exists(input_path) or not os.path.exists(targets_path):
        print(f"错误：输入文件 '{input_path}' 或 '{targets_path}' 不存在。请检查文件名和路径。")
        return

    # 2. 统计目标用户数量
    try:
        with open(targets_path, 'r', encoding='utf-8') as f:
            # 过滤掉空行
            num_users = sum(1 for line in f if line.strip())
        if num_users == 0:
            print("错误：'targets.txt' 中没有找到任何用户数据。")
            return
        print(f"在 '{targets_path}' 中检测到 {num_users} 个用户。")
    except Exception as e:
        print(f"读取 '{targets_path}' 文件时出错: {e}")
        return

    # 3. 读取原始猜测文件 (尝试使用 GBK 解码)
    all_guesses = []
    try:
        with open(input_path, 'r', encoding='gbk', errors='ignore') as infile:
            all_guesses = [line.strip() for line in infile if line.strip()]
        print(f"成功从 '{input_path}' 中读取 {len(all_guesses)} 条猜测记录。")
    except UnicodeDecodeError:
        print(f"错误：使用 GBK 编码打开 '{input_path}' 失败。请确认文件编码是否为 GBK 或 GB2312。")
        return
    except Exception as e:
        print(f"读取 '{input_path}' 文件时发生未知错误: {e}")
        return
    
    total_guesses = len(all_guesses)
    if total_guesses == 0:
        print("警告: 输入文件'output.txt'为空，没有内容可以处理。")
        return

    # 4. 检查猜测数量是否与预期匹配
    expected_total = num_users * guesses_per_user
    if total_guesses != expected_total:
        print("\n--- 警告 ---")
        print(f"文件中的猜测总数 ({total_guesses}) 与预期数量 ({expected_total}) 不匹配。")
        print(f"这可能是因为 'GUESSES_PER_USER' ({guesses_per_user}) 的值与 config.ini 中的设置不一致。")
        print("脚本将继续处理，但结果可能不准确。")
        print("--------------\n")
        # 修正每个用户的猜测数，以实际情况为准
        if num_users > 0:
            guesses_per_user = total_guesses // num_users
        else:
            print("错误：用户数为0，无法继续处理。")
            return


    # 5. 重构内容并写入新文件
    try:
        with open(output_path, 'w', encoding='utf-8') as outfile:
            processed_count = 0
            for i in range(num_users):
                # 获取当前用户的猜测切片
                start_index = i * guesses_per_user
                end_index = start_index + guesses_per_user
                user_guesses = all_guesses[start_index:end_index]

                # --- 这是唯一的修改点 ---
                # 写入该用户的猜测列表
                for guess_line in user_guesses:
                    # 分割字符串，只取制表符前的密码部分
                    password_only = guess_line.split('\t')[0]
                    outfile.write(password_only + '\n')
                # --- 修改结束 ---
                
                processed_count += len(user_guesses)

                # 如果不是最后一个用户，则写入分隔符
                if i < num_users - 1:
                    outfile.write('<END>\n')
            
            print(f"处理完成！已将 {processed_count} 条记录和 {num_users - 1} 个分隔符写入到 '{output_path}'。")
            print(f"文件已使用 UTF-8 编码保存。")

    except Exception as e:
        print(f"写入输出文件时出错: {e}")

# --- 运行脚本 ---
if __name__ == "__main__":
    reformat_guesses_from_file(input_filename, targets_filename, GUESSES_PER_USER, output_filename)
