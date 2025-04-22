# 这个文件包含Oyente项目中使用的各种辅助函数。
# 这些函数涵盖了类型检查、数值转换、Z3求解器交互、
# 变量处理、文件操作、外部命令执行以及一些特定于合约分析的工具。

import shlex  # 用于解析简单的类shell语法
import subprocess  # 用于创建子进程，执行外部命令
import json  # 用于处理JSON数据
import mmap  # 用于内存映射文件，提高大文件读取效率
import os  # 提供与操作系统交互的功能
import errno  # 定义标准的系统错误号
import signal  # 用于处理信号
import csv  # 用于读写CSV文件
import re  # 正则表达式操作
import difflib  # 用于比较序列，例如文件差异
import six  # Python 2/3 兼容性库
from z3 import *  # Z3定理证明器库，用于符号执行和约束求解
from z3.z3util import get_vars  # 从Z3表达式中提取变量

def ceil32(x):
    """
    将整数 x 向上取整到最接近的 32 的倍数。
    常用于计算EVM内存扩展的大小。

    :param x: 需要向上取整的整数。
    :return: 向上取整到32倍数的结果。
    """
    return x if x % 32 == 0 else x + 32 - (x % 32)

def isSymbolic(value):
    """
    检查一个值是否是符号变量（即非Python原生整数类型）。
    在符号执行中，用于区分具体值和Z3符号表达式。

    :param value: 需要检查的值。
    :return: 如果值是符号变量返回True，否则返回False。
    """
    # six.integer_types 包含了 Python 2/3 中的整数类型 (int, long)
    return not isinstance(value, six.integer_types)

def isReal(value):
    """
    检查一个值是否是具体值（即Python原生整数类型）。

    :param value: 需要检查的值。
    :return: 如果值是具体整数返回True，否则返回False。
    """
    return isinstance(value, six.integer_types)

def isAllReal(*args):
    """
    检查所有传入的参数是否都是具体值。

    :param args: 一个或多个需要检查的值。
    :return: 如果所有参数都是具体整数返回True，否则返回False。
    """
    for element in args:
        if isSymbolic(element):
            return False
    return True

def to_symbolic(number):
    """
    将一个具体整数转换为Z3的BitVecVal（位向量值）。
    如果输入已经是符号变量，则直接返回。

    :param number: 需要转换的整数或已有的符号变量。
    :return: 对应的Z3 BitVecVal（256位）或原始符号变量。
    """
    if isReal(number):
        # 创建一个256位的Z3位向量值
        return BitVecVal(number, 256)
    return number

def to_unsigned(number):
    """
    将一个可能为负的整数转换为EVM兼容的256位无符号整数。
    EVM使用模2^256算术。

    :param number: 需要转换的整数。
    :return: 对应的256位无符号整数。
    """
    if number < 0:
        # 负数通过加 2^256 转换为正数
        return number + 2**256
    return number

def to_signed(number):
    """
    将一个256位无符号整数转换为有符号整数。
    EVM的有符号整数范围是 [-2^255, 2^255 - 1]。

    :param number: 需要转换的256位无符号整数。
    :return: 对应的有符号整数。
    """
    # 如果数值大于 2^255 - 1，则表示负数
    if number >= 2**(256 - 1):
        # 计算对应的负数值
        return (number - 2**256)
    else:
        return number

def check_sat(solver, pop_if_exception=True):
    """
    安全地检查Z3求解器的可满足性。
    处理可能的未知状态和异常。

    :param solver: Z3 Solver对象。
    :param pop_if_exception: 如果发生异常，是否自动调用solver.pop()回滚状态。
    :return: Z3求解器的检查结果 (sat, unsat)。
    :raises Z3Exception: 如果求解结果是unknown或发生其他Z3异常。
    """
    try:
        ret = solver.check()
        if ret == unknown:
            # 如果结果未知，抛出包含原因的异常
            raise Z3Exception(solver.reason_unknown())
    except Exception as e:
        if pop_if_exception:
            # 发生异常时，根据参数决定是否回滚求解器状态
            solver.pop()
        raise e  # 重新抛出异常
    return ret

def custom_deepcopy(input_dict):
    """
    实现一个简化的深拷贝，主要用于拷贝包含基本类型、列表和字典的字典。
    注意：这个实现可能不如标准库的 `copy.deepcopy` 完整。

    :param input_dict: 需要深拷贝的字典。
    :return: 深拷贝后的新字典。
    """
    output = {}
    for key in input_dict:
        value = input_dict[key]
        if isinstance(value, list):
            # 拷贝列表
            output[key] = list(value)
        elif isinstance(value, dict):
            # 递归拷贝字典
            output[key] = custom_deepcopy(value)
        else:
            # 直接赋值（适用于基本类型和不可变对象）
            output[key] = value
    return output

def is_storage_var(var):
    """
    检查一个变量名（字符串或Z3变量）是否表示合约的存储变量。
    Oyente中存储变量通常以 "Ia_store" 开头。

    :param var: Z3变量对象或变量名字符串。
    :return: 如果是存储变量返回True，否则返回False。
    """
    # 如果输入是Z3变量对象，获取其名称
    if not isinstance(var, str): var = var.decl().name()
    # 检查名称是否以 "Ia_store" 开头
    return var.startswith('Ia_store')

def copy_global_values(global_state):
    """
    从给定的全局状态字典中仅复制与合约存储相关的值/变量。
    目前只复制 'Ia' (表示合约存储)。
    TODO: 未来可能需要添加余额等其他全局状态。

    :param global_state: 包含全局状态的字典。
    :return: 一个只包含合约存储状态的新字典。
    """
    # 'Ia' 键通常存储合约的存储状态 (地址 -> 值/表达式)
    return global_state['Ia']

def is_in_expr(var, expr):
    """
    检查一个给定的变量是否存在于一个Z3表达式中。

    :param var: 需要检查的变量名（字符串）。
    :param expr: Z3表达式。
    :return: 如果变量存在于表达式中返回True，否则返回False。
    """
    # 获取表达式中的所有Z3变量对象
    list_vars = get_vars(expr)
    # 将变量对象转换为变量名集合，便于快速查找
    set_vars = set(i.decl().name() for i in list_vars)
    # 检查目标变量名是否在集合中
    return var in set_vars

def has_storage_vars(expr, storage_vars):
    """
    检查一个Z3表达式是否包含任何存储变量。

    :param expr: Z3表达式。
    :param storage_vars: 一个包含存储变量Z3对象的集合或列表。
    :return: 如果表达式中包含任何指定的存储变量返回True，否则返回False。
    """
    # 获取表达式中的所有Z3变量对象
    list_vars = get_vars(expr)
    # 遍历表达式中的变量
    for var in list_vars:
        # 检查变量是否存在于给定的存储变量集合中
        if var in storage_vars:
            return True
    return False

def get_all_vars(exprs):
    """
    从一个Z3表达式列表中提取所有变量。

    :param exprs: Z3表达式列表。
    :return: 包含所有提取到的Z3变量对象的列表。
    """
    ret_vars = []
    for expr in exprs:
        # 确保处理的是Z3表达式
        if is_expr(expr):
            # 提取变量并添加到结果列表
            ret_vars += get_vars(expr)
    return ret_vars

def get_storage_position(var):
    """
    从存储变量名中提取存储位置（地址）。
    存储变量名格式通常为 "Ia_store_<position>" 或 "Ia_store_<position>-<...>".

    :param var: Z3存储变量对象或变量名字符串。
    :return: 存储位置（整数或字符串）。
    """
    # 如果输入是Z3变量对象，获取其名称
    if not isinstance(var, str): var = var.decl().name()
    # 按 '-' 分割，取第二部分作为位置
    pos = var.split('-')[1]
    try:
        # 尝试将位置转换为整数
        return int(pos)
    except ValueError:
        # 如果转换失败，返回原始字符串（可能表示符号地址）
        return pos

def rename_vars(pcs, global_states):
    """
    重命名路径条件(pcs)和全局状态(global_states)中的变量，
    用于区分两条不同路径分析中的同名变量。
    通常将旧路径中的变量名添加 "_old" 后缀。
    只重命名被修改过的存储变量或非存储变量。

    :param pcs: 旧路径的路径条件列表 (Z3表达式)。
    :param global_states: 旧路径修改过的全局存储状态 (地址 -> Z3表达式)。
    :return: 一个元组，包含重命名后的路径条件列表和全局状态字典。
    """
    ret_pcs = []  # 存储重命名后的路径条件
    vars_mapping = {}  # 存储旧变量到新变量的映射

    # 遍历路径条件
    for expr in pcs:
        if is_expr(expr):
            list_vars = get_vars(expr)
            for var in list_vars:
                # 如果变量已在映射中，直接替换
                if var in vars_mapping:
                    expr = substitute(expr, (var, vars_mapping[var]))
                    continue

                var_name = var.decl().name()
                # 检查是否是存储变量
                if is_storage_var(var):
                    pos = get_storage_position(var)
                    # 如果存储变量未在 global_states 中被修改，则不重命名
                    if pos not in global_states:
                        continue

                # 对于非存储变量或被修改的存储变量，创建新名称和新变量
                new_var_name = var_name + '_old'
                # 假设所有变量都是256位
                new_var = BitVec(new_var_name, 256)
                # 添加到映射
                vars_mapping[var] = new_var
                # 在表达式中替换
                expr = substitute(expr, (var, vars_mapping[var]))
        ret_pcs.append(expr)

    ret_gs = {}  # 存储重命名后的全局状态
    # 遍历全局状态
    for storage_addr in global_states:
        expr = global_states[storage_addr]
        if is_expr(expr):
            list_vars = get_vars(expr)
            for var in list_vars:
                # 如果变量已在映射中，直接替换
                if var in vars_mapping:
                    expr = substitute(expr, (var, vars_mapping[var]))
                    continue

                var_name = var.decl().name()
                # 检查是否是存储变量
                if is_storage_var(var):
                    pos = get_storage_position(var)
                    # 如果存储变量未在 global_states 中被修改，则不重命名
                    # 注意：这里的逻辑与上面路径条件部分相同，确保一致性
                    if pos not in global_states:
                        continue

                # 对于非存储变量或被修改的存储变量，创建新名称和新变量
                new_var_name = var_name + '_old'
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                expr = substitute(expr, (var, vars_mapping[var]))
        ret_gs[storage_addr] = expr

    return ret_pcs, ret_gs

def split_dicts(filename, nsub=500):
    """
    将一个大的JSON文件（假设其内容是一个字典）拆分成多个小的JSON文件。
    每个小文件包含原始字典的一部分条目。

    :param filename: 输入的JSON文件名。
    :param nsub: 每个小文件包含的最大条目数。
    """
    with open(filename) as json_file:
        c = json.load(json_file)  # 加载JSON数据
        current_file = {}  # 当前小文件的内容
        file_index = 1  # 小文件的序号
        # 遍历原始字典的键值对
        # 注意：Python 2/3 的字典迭代方式不同，six.iteritems() 可兼容
        for u, v in six.iteritems(c):
            current_file[u] = v
            # 如果当前小文件达到指定大小
            if len(current_file) == nsub:
                # 构造小文件名
                out_filename = filename.split(".")[0] + "_" + str(file_index) + '.json'
                # 写入小文件
                with open(out_filename, 'w') as outfile:
                    json.dump(current_file, outfile)
                file_index += 1
                current_file.clear()  # 清空，准备下一个小文件
        # 处理剩余不足 nsub 条目的数据
        if len(current_file):
            out_filename = filename.split(".")[0] + "_" + str(file_index) + '.json'
            with open(out_filename, 'w') as outfile:
                json.dump(current_file, outfile)
            current_file.clear()

def do_split_dicts():
    """
    一个辅助函数，用于批量拆分名为 "contract0.json" 到 "contract10.json" 的文件。
    拆分后删除原始文件。
    """
    for i in range(11):
        filename = "contract" + str(i) + ".json"
        split_dicts(filename)
        os.remove(filename)

def run_re_file(re_str, fn):
    """
    在一个文件中使用内存映射高效地查找所有匹配正则表达式的字符串。

    :param re_str: 正则表达式字符串。
    :param fn: 文件名。
    :return: 包含所有匹配项的列表。
    :raises OSError: 如果文件不存在或无法访问。
    """
    size = os.stat(fn).st_size  # 获取文件大小
    with open(fn, 'r') as tf:
        # 创建内存映射对象
        # access=mmap.ACCESS_READ 表示只读访问
        data = mmap.mmap(tf.fileno(), size, access=mmap.ACCESS_READ)
        # 在内存映射数据上执行正则表达式查找
        return re.findall(re_str, data)

def get_contract_info(contract_addr):
    """
    从 Etherscan 网站获取指定合约地址的交易数量和ETH余额。
    首先尝试从本地缓存文件读取，如果失败则通过wget下载网页并解析。

    :param contract_addr: 以太坊合约地址字符串。
    :return: 一个元组 (交易数量字符串, ETH余额字符串)。如果获取失败则为 "unknown"。
    """
    print("Getting info for contracts... " + contract_addr)
    # 定义缓存文件名
    file_name1 = "tmp/" + contract_addr + "_txs.html"  # 交易信息页面
    file_name2 = "tmp/" + contract_addr + ".html"      # 地址信息页面

    txs = "unknown"
    value = "unknown"
    # 定义用于提取信息的正则表达式
    re_txs_value = r"<span>A total of (.+?) transactions found for address</span>"
    re_str_value = r"<td>ETH Balance:\n<\/td>\n<td>\n(.+?)\n<\/td>"

    try:
        # 尝试从缓存文件读取
        txs = run_re_file(re_txs_value, file_name1)
        value = run_re_file(re_str_value, file_name2)
    except Exception as e:
        # 如果缓存读取失败，尝试下载并解析
        try:
            # 使用wget下载交易信息页面
            os.system("wget -O %s http://etherscan.io/txs?a=%s" % (file_name1, contract_addr))
            txs = run_re_file(re_txs_value, file_name1)

            # 使用wget下载地址信息页面
            os.system("wget -O %s https://etherscan.io/address/%s" % (file_name2, contract_addr))
            value = run_re_file(re_str_value, file_name2)
        except Exception as e:
            # 如果下载或解析再次失败，则保持 "unknown"
            pass
    # 返回提取到的信息（可能是列表，取第一个元素或保持unknown）
    txs_result = txs[0] if isinstance(txs, list) and txs else "unknown"
    value_result = value[0] if isinstance(value, list) and value else "unknown"
    return txs_result, value_result

def get_contract_stats(list_of_contracts):
    """
    读取一个包含合约分析结果的文件，并为每个合约获取链上统计信息（余额、交易数），
    然后将所有信息写入一个新的CSV文件 "concurr.csv"。

    :param list_of_contracts: 包含合约分析结果的文件路径。
                              文件格式预期为每行: <地址> <路径数> <并发对数> [备注...]
    """
    with open("concurr.csv", "w") as stats_file:
        fp = csv.writer(stats_file, delimiter=',')
        # 写入CSV表头
        fp.writerow(["Contract address", "No. of paths", "No. of concurrency pairs", "Balance", "No. of TXs", "Note"])
        with open(list_of_contracts, "r") as f:
            for contract_line in f.readlines():
                parts = contract_line.split()
                if not parts: continue # 跳过空行
                contract_addr = parts[0]
                # 获取链上信息
                txs, value = get_contract_info(contract_addr)
                # 写入CSV行
                fp.writerow([contract_addr, parts[1], parts[2],
                             value, txs, ' '.join(parts[3:])]) # 将剩余部分作为备注

def get_time_dependant_contracts(list_of_contracts):
    """
    读取一个包含时间依赖性分析结果的文件，为每个合约获取链上统计信息（余额、交易数），
    并将结果写入一个新的CSV文件 "time.csv"。

    :param list_of_contracts: 包含时间依赖性分析结果的文件路径。
                              文件格式预期为每行包含合约地址（可能在文件名中）。
    """
    with open("time.csv", "w") as stats_file:
        fp = csv.writer(stats_file, delimiter=',')
        # 写入CSV表头
        fp.writerow(["Contract address", "Balance", "No. of TXs"])
        with open(list_of_contracts, "r") as f:
            for contract_line in f.readlines():
                contract_line = contract_line.strip()
                if not contract_line:
                    continue
                # 从文件名或行内容中提取合约地址（假设格式如 "stats/tmp_<addr>.evm" 或类似）
                # 这个提取逻辑可能需要根据实际文件名格式调整
                match = re.search(r'0x[a-fA-F0-9]{40}', contract_line)
                if not match: continue # 如果找不到地址，跳过
                contract_addr = match.group(0)
                # 获取链上信息
                txs, value = get_contract_info(contract_addr)
                # 写入CSV行
                fp.writerow([contract_addr, value, txs])

def get_distinct_contracts(list_of_contracts="concurr.csv"):
    """
    分析一个包含合约统计信息的CSV文件，尝试找出代码相似的合约。
    通过比较路径数、并发对数以及反汇编代码的差异来实现。
    标记相似的合约，以便后续可能只分析其中一个代表。

    :param list_of_contracts: 输入的CSV文件名。
    """
    flag = []  # 存储每个合约的代表合约索引
    with open(list_of_contracts, "rb") as csvfile:
        # 读取CSV文件，跳过表头
        contracts_data = csvfile.readlines()[1:]
        n = len(contracts_data)
        # 初始化flag，每个合约最初都代表自己
        for i in range(n):
            flag.append(i)

        # 两两比较合约
        for i in range(n):
            # 如果合约i已经被标记为与之前的某个合约相似，则跳过
            if flag[i] != i:
                continue

            # 解析合约i的信息
            parts_i = contracts_data[i].decode('utf-8', 'ignore').split(",")
            if len(parts_i) < 3: continue # 确保数据格式正确
            contract_i = parts_i[0]
            try:
                npath_i = int(parts_i[1])
                npair_i = int(parts_i[2])
            except ValueError:
                continue # 跳过无法解析的行

            # 假设反汇编文件存储在 "stats/tmp_<addr>.evm"
            file_i = "stats/tmp_" + contract_i + ".evm"
            print(" reading file " + file_i)

            # 与后续合约j比较
            for j in range(i + 1, n):
                # 如果合约j已被标记，跳过
                if flag[j] != j:
                    continue

                # 解析合约j的信息
                parts_j = contracts_data[j].decode('utf-8', 'ignore').split(",")
                if len(parts_j) < 3: continue
                contract_j = parts_j[0]
                try:
                    npath_j = int(parts_j[1])
                    npair_j = int(parts_j[2])
                except ValueError:
                    continue

                # 初步筛选：路径数和并发对数必须相同
                if (npath_i == npath_j) and (npair_i == npair_j):
                    file_j = "stats/tmp_" + contract_j + ".evm"

                    try:
                        # 比较反汇编代码
                        with open(file_i, 'r') as f1, open(file_j, 'r') as f2:
                            code_i = f1.readlines()
                            code_j = f2.readlines()

                            # 如果代码长度差异过大，认为不相似
                            if abs(len(code_i) - len(code_j)) >= 5:
                                continue

                            # 使用difflib计算代码差异
                            diff = difflib.ndiff(code_i, code_j)
                            ndiff = 0
                            for line in diff:
                                # 计算增删行的数量
                                if line.startswith("+") or line.startswith("-"):
                                    ndiff += 1

                            # 如果差异行数小于阈值（例如10），认为它们相似
                            if ndiff < 10:
                                # 将合约j标记为与合约i相似
                                flag[j] = i
                    except IOError:
                        # 处理文件不存在或无法读取的情况
                        print("Warning: Could not compare files %s and %s" % (file_i, file_j))
                        continue
    # 打印最终的相似性标记结果
    print(flag)

def run_command(cmd):
    """
    执行一个外部shell命令，并返回其标准输出。
    标准错误输出被重定向到/dev/null。

    :param cmd: 需要执行的命令字符串。
    :return: 命令的标准输出字符串（UTF-8解码）。
    """
    FNULL = open(os.devnull, 'w')  # 打开/dev/null用于丢弃错误输出
    # 使用shlex.split处理命令字符串，避免shell注入风险
    # 创建子进程执行命令
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    # 获取命令的标准输出，并进行UTF-8解码
    stdout_data = solc_p.communicate()[0]
    return stdout_data.decode('utf-8', 'strict')

def run_command_with_err(cmd):
    """
    执行一个外部shell命令，并同时返回其标准输出和标准错误输出。

    :param cmd: 需要执行的命令字符串。
    :return: 一个元组 (标准输出字符串, 标准错误字符串)，均进行UTF-8解码。
    """
    # 创建子进程执行命令，捕获标准输出和标准错误
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # 获取命令的标准输出和标准错误
    out, err = solc_p.communicate()
    # 进行UTF-8解码
    out = out.decode('utf-8', 'strict')
    err = err.decode('utf-8', 'strict')
    return out, err