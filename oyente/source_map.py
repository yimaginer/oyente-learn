# 这个文件定义了用于处理Solidity源代码映射的类和方法。
# 主要功能是将EVM字节码指令的程序计数器(PC)映射回原始Solidity源代码的位置（行号、列号），
# 并提供访问源代码片段、变量名、函数签名等信息的功能。

import re  # 正则表达式库
import six  # Python 2/3 兼容性库
import ast  # 抽象语法树库 (用于解析变量名)
import json # JSON 数据处理库

import global_params # 导入全局参数

from utils import run_command # 导入执行外部命令的工具函数
from ast_helper import AstHelper # 导入处理Solidity AST的辅助类

class Source:
    """
    表示单个Solidity源文件及其内容。
    """
    def __init__(self, filename):
        """
        初始化Source对象。

        :param filename: 源文件的路径。
        """
        self.filename = filename # 文件名
        self.content = self._load_content() # 加载文件内容
        # 换行位置列表，存储每个换行符在文件内容中的索引
        self.line_break_positions = self._load_line_break_positions()

    def _load_content(self):
        """
        从文件中加载内容并解码为UTF-8字符串。

        :return: 文件内容的字符串。
        """
        try:
            with open(self.filename, 'rb') as f: # 以二进制读取模式打开文件
                content = f.read().decode('UTF-8') # 读取内容并解码
            return content
        except IOError:
            # 处理文件未找到或无法读取的情况
            print("Error: Source file not found or cannot be read: %s" % self.filename)
            return "" # 返回空字符串表示错误

    def _load_line_break_positions(self):
        """
        计算并返回文件中所有换行符的位置列表。

        :return: 包含所有换行符索引的列表。
        """
        # 列表推导式，遍历文件内容，记录每个'\n'的索引
        return [i for i, letter in enumerate(self.content) if letter == '\n']

# SourceMap 类用于管理和查询源代码映射信息
# ast_helper: AstHelper类的实例，存储着合约的各种索引和输出合约索引和状态的辅助类函数。
# position_groups：字典，存储从solc编译器获取的编译信息，包括字节码指令(asm)和辅助数据(auxdata)。
#                  其中的 'begin' 和 'end' 键（在asm部分）映射着指令对应的源代码字符串的开始和结束位置。
class SourceMap:
    """
    管理Solidity源代码映射信息，提供PC到源代码位置的转换等功能。
    使用类变量缓存从编译器获取的共享信息，避免重复编译。
    """
    # --- 类变量，用于缓存共享信息 ---
    parent_filename = "" # 主输入文件名 (例如 a.sol)
    position_groups = {} # 缓存从 `solc --combined-json asm` 获取的编译结果
    sources = {} # 缓存已加载的 Source 对象 {filename: Source_instance}
    ast_helper = None # 缓存 AstHelper 实例
    func_to_sig_by_contract = {} # 缓存从 `solc --combined-json hashes` 获取的函数签名 {contract_qname: {'hashes':{...}}}
    remap = "" # 缓存导入重映射设置
    allow_paths = "" # 缓存允许的导入路径设置
    # --- ---

    # cname (合约限定名，格式: 路径/文件名.sol:合约名)
    # parent_filename (主输入文件名，格式: 路径/文件名.sol)
    def __init__(self, cname, parent_filename, input_type, root_path="", remap="", allow_paths=""):
        """
        初始化SourceMap对象，用于特定合约。

        :param cname: 合约的完全限定名称 (e.g., "path/to/file.sol:MyContract")。
        :param parent_filename: 包含该合约的主Solidity文件名。
        :param input_type: 输入类型 ("solidity", "standard json")。
        :param root_path: 项目根路径 (主要用于在线版本)。
        :param remap: Solidity导入重映射设置。
        :param allow_paths: Solidity允许的导入路径。
        """
        self.root_path = root_path # 项目根路径
        self.cname = cname # 当前处理的合约限定名
        self.input_type = input_type # 输入类型

        # --- 初始化共享信息 (如果尚未加载) ---
        # 使用类变量作为缓存，避免对同一个主文件重复执行solc和AST分析
        if not SourceMap.parent_filename:
            SourceMap.remap = remap # 缓存重映射设置
            SourceMap.allow_paths = allow_paths # 缓存允许路径设置
            SourceMap.parent_filename = parent_filename # 缓存主文件名

            # 根据输入类型加载编译后的位置信息 (asm)
            if input_type == "solidity":
                 # 调用solc编译生成对应合约的asm和Solidity版本信息
                SourceMap.position_groups = SourceMap._load_position_groups()
            elif input_type == "standard json":
                # 从标准JSON输出文件加载位置信息
                SourceMap.position_groups = SourceMap._load_position_groups_standard_json()
            else:
                raise Exception("There is no such type of input") # 不支持的输入类型

            # 初始化AST辅助类，用于解析合约结构
            SourceMap.ast_helper = AstHelper(SourceMap.parent_filename, input_type, SourceMap.remap, SourceMap.allow_paths)
            # 获取所有合约的函数签名信息
            SourceMap.func_to_sig_by_contract = SourceMap._get_sig_to_func_by_contract()
        # --- ---

        # --- 初始化当前合约实例的特定信息 ---
        # 获取当前合约的源代码内容和文件名对应的Source对象
        self.source = self._get_source()
        # 获取当前合约编译后的指令位置列表 [{'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '60'} ...]
        self.positions = self._get_positions()
        # 指令PC到源代码位置信息的映射 {pc: {'begin': offset, 'end': offset}}
        self.instr_positions = {} # 这个字典会在符号执行过程中填充
        # 获取当前合约的状态变量名称集合
        self.var_names = self._get_var_names()
        # 获取当前合约中函数调用的源代码字符串列表 ['bytes32(11111)', 'owner.send(reward)', ...]
        self.func_call_names = self._get_func_call_names()
        # 获取当前合约中外部调用(call, delegatecall, callcode)的目标合约及源代码位置对
        self.callee_src_pairs = self._get_callee_src_pairs()
        # 获取当前合约的函数名到参数信息的映射
        self.func_name_to_params = self._get_func_name_to_params()
        # 获取当前合约的函数签名(hash)到函数名的映射 {'a0d7afb7': 'diff()', ...}
        self.sig_to_func = self._get_sig_to_func()
        # --- ---

    def get_source_code(self, pc):
        """
        根据程序计数器(PC)获取对应的源代码片段。

        :param pc: EVM指令的程序计数器。
        :return: 对应的源代码字符串，如果找不到则返回空字符串。
        """
        try:
            # 从instr_positions获取PC对应的源代码偏移量
            pos = self.instr_positions[pc]
        except KeyError:
            # 如果PC不在映射中，返回空字符串
            return ""
        begin = pos['begin'] # 开始偏移量
        end = pos['end'] # 结束偏移量
        # 从源代码内容中截取对应片段
        return self.source.content[begin:end+1] # 注意：结束索引需要+1

    def get_source_code_from_src(self, src):
        """
        根据solc生成的src字符串获取对应的源代码片段。
        src格式: "起始偏移量:长度:源文件ID"

        :param src: solc生成的源代码位置字符串。
        :return: 对应的源代码字符串。
        """
        src_parts = src.split(":")
        start = int(src_parts[0]) # 起始偏移量
        length = int(src_parts[1]) # 长度
        end = start + length # 计算结束偏移量
        # 从源代码内容中截取对应片段
        return self.source.content[start:end]

    def get_buggy_line(self, pc):
        """
        根据PC获取包含该指令的源代码行（从行首到指令结束）。
        用于在报告错误时显示相关的代码行。

        :param pc: EVM指令的程序计数器。
        :return: 包含指令的源代码行字符串，如果找不到则返回空字符串。
        """
        try:
            # 获取PC对应的源代码偏移量
            pos = self.instr_positions[pc]
        except KeyError:
            return ""
        # 获取PC对应的行列信息
        location = self.get_location(pc)
        if not location or location['begin'] is None:
            return "" # 如果无法获取位置信息，返回空

        line_num = location['begin']['line'] # 获取起始行号
        # 处理行号可能为0或超出范围的情况
        if line_num <= 0 or line_num > len(self.source.line_break_positions):
             # 如果行号无效，尝试直接使用偏移量获取代码
             begin = pos['begin']
             end = pos['end']
             # 简单的回溯查找行首（可能不精确）
             while begin > 0 and self.source.content[begin-1] != '\n':
                 begin -= 1
             return self.source.content[begin:end+1]

        # 获取该行在文件中的起始偏移量
        # 如果是第一行(line_num=0)，起始偏移量为0
        # 否则，起始偏移量是上一行换行符位置+1
        begin = 0 if line_num == 0 else self.source.line_break_positions[line_num - 1] + 1
        end = pos['end'] # 指令的结束偏移量
        # 截取从行首到指令结束的源代码
        return self.source.content[begin:end+1]

    def get_buggy_line_from_src(self, src):
        """
        根据solc的src字符串获取包含该位置的源代码行。

        :param src: solc生成的源代码位置字符串。
        :return: 包含该位置的源代码行字符串。
        """
        # 将src字符串转换为偏移量字典 {'begin': offset, 'end': offset}
        pos = self._convert_src_to_pos(src)
        # 获取src对应的行列信息
        location = self.get_location_from_src(src)
        if not location or location['begin'] is None:
             return "" # 如果无法获取位置信息，返回空

        line_num = location['begin']['line'] # 获取起始行号
        # 处理行号可能为0或超出范围的情况
        if line_num <= 0 or line_num > len(self.source.line_break_positions):
             # 如果行号无效，尝试直接使用偏移量获取代码
             begin = pos['begin']
             end = pos['end']
             while begin > 0 and self.source.content[begin-1] != '\n':
                 begin -= 1
             return self.source.content[begin:end+1]

        # 获取该行在文件中的起始偏移量
        begin = 0 if line_num == 0 else self.source.line_break_positions[line_num - 1] + 1
        end = pos['end'] # 结束偏移量
        # 截取从行首到结束偏移量的源代码
        return self.source.content[begin:end+1]

    def get_location(self, pc):
        """
        根据PC获取源代码中的位置（行号和列号）。

        :param pc: EVM指令的程序计数器。
        :return: 包含起始和结束行列信息的字典，格式: {'begin': {'line': l, 'column': c}, 'end': {'line': l, 'column': c}}。
                 如果找不到位置则返回空字典或包含None的字典。
        """
        try:
            # 获取PC对应的偏移量
            pos = self.instr_positions[pc]
            # 将偏移量转换为行列信息
            return self._convert_offset_to_line_column(pos)
        except KeyError:
            return {} # PC未找到

    def get_location_from_src(self, src):
        """
        根据solc的src字符串获取源代码中的位置（行号和列号）。

        :param src: solc生成的源代码位置字符串。
        :return: 包含起始和结束行列信息的字典。
        """
        # 将src字符串转换为偏移量字典
        pos = self._convert_src_to_pos(src)
        # 将偏移量转换为行列信息
        return self._convert_offset_to_line_column(pos)

    def get_parameter_or_state_var(self, var_name):
        """
        检查给定的变量名是否是当前合约的参数或状态变量。
        尝试解析变量名，并检查其根标识符是否存在于已知变量名集合中。

        :param var_name: 需要检查的变量名字符串 (可能包含点号或索引，如 "balances[msg.sender]").
        :return: 如果是参数或状态变量，返回原始变量名字符串；否则返回None。
        """
        try:
            # 使用ast库解析变量名字符串，提取其中的标识符(Name)
            # 例如 "balances[msg.sender]" 会提取出 "balances" 和 "msg", "sender"
            names = [
                node.id for node in ast.walk(ast.parse(var_name))
                if isinstance(node, ast.Name)
            ]
            # 检查第一个提取到的标识符 (通常是变量的根名称) 是否在已知变量名集合中
            if names and names[0] in self.var_names:
                return var_name # 如果是，返回原始名称
        except SyntaxError:
            # 如果变量名无法被ast解析 (可能不是有效的Python标识符或表达式)
            # 直接检查原始名称是否在已知变量名中
            if var_name in self.var_names:
                return var_name
        except Exception:
            # 捕获其他可能的解析错误
            return None
        return None # 如果不是参数或状态变量，返回None

    def _convert_src_to_pos(self, src):
        """
        将solc的src字符串 ("start:length:fileId") 转换为偏移量字典。

        :param src: solc生成的源代码位置字符串。
        :return: 包含起始和结束偏移量的字典 {'begin': offset, 'end': offset}。
        """
        pos = {}
        src_parts = src.split(":")
        pos['begin'] = int(src_parts[0]) # 起始偏移量
        length = int(src_parts[1]) # 长度
        pos['end'] = pos['begin'] + length - 1 # 计算结束偏移量 (包含)
        return pos

    def _get_sig_to_func(self):
        """
        获取当前合约的函数签名(hash)到函数签名的映射。
        例如: {'a0d7afb7': 'diff()', ...}

        :return: 签名到函数签名的字典。
        """
        try:
            # 从类变量缓存中获取当前合约的 函数签名->哈希 映射
            func_to_sig = SourceMap.func_to_sig_by_contract[self.cname]['hashes']
            # 反转字典，得到 哈希->函数签名 映射
            return dict((sig, func) for func, sig in six.iteritems(func_to_sig))
        except KeyError:
            # 如果当前合约没有函数签名信息 (可能是接口或库)
            return {}

    def _get_func_name_to_params(self):
        """
        获取当前合约的函数名到参数详细信息的映射。
        并计算每个参数在calldata中的相对位置。

        :return: 字典，键为函数名，值为参数信息列表。
                 每个参数信息是一个字典，包含 'name', 'type', 'position' 等。
        """
        # 从AstHelper获取函数名到参数基本信息的映射
        func_name_to_params = SourceMap.ast_helper.get_func_name_to_params(self.cname)
        # 计算每个参数在calldata中的位置 (从0开始计数)
        for func_name in func_name_to_params:
            calldataload_position = 0 # calldata中的位置计数器
            for param in func_name_to_params[func_name]:
                # 数组类型会占用其声明的大小个slot (这里简化处理，可能不完全准确)
                if param.get('type') == 'ArrayTypeName':
                    param['position'] = calldataload_position
                    # 假设数组元素占用1个slot，更新位置计数器
                    # 注意：这可能不适用于动态数组或结构体数组
                    array_size = param.get('value', 1) # 获取数组大小，默认为1
                    calldataload_position += array_size
                else:
                    # 非数组类型占用1个slot
                    param['position'] = calldataload_position
                    calldataload_position += 1
        return func_name_to_params

    def _get_source(self):
        """
        获取当前合约对应的Source对象。
        如果尚未加载，则创建并缓存。

        :return: Source对象。
        """
        # 从合约限定名中提取文件名
        fname = self.get_filename()
        # 检查缓存中是否已有该文件的Source对象
        if fname not in SourceMap.sources:
            # 如果没有，创建新的Source对象并存入缓存
            SourceMap.sources[fname] = Source(fname)
        # 返回缓存中的Source对象
        return SourceMap.sources[fname]

    def _get_callee_src_pairs(self):
        """
        从AstHelper获取当前合约中外部调用(call, delegatecall, callcode)的目标合约及源代码位置对。

        :return: (目标合约限定名, src字符串) 的列表。
        """
        return SourceMap.ast_helper.get_callee_src_pairs(self.cname)

    def _get_var_names(self):
        """
        从AstHelper获取当前合约的状态变量名称列表。

        :return: 状态变量名称的列表。
        """
        return SourceMap.ast_helper.extract_state_variable_names(self.cname)

    def _get_func_call_names(self):
        """
        从AstHelper获取当前合约中所有函数调用的源代码字符串。

        :return: 函数调用源代码字符串的列表。
        """
        # 从AstHelper获取函数调用的src位置列表
        func_call_srcs = SourceMap.ast_helper.extract_func_call_srcs(self.cname)
        func_call_names = []
        # 遍历每个src位置
        for src in func_call_srcs:
            # 将src字符串转换为起始和结束偏移量
            src_parts = src.split(":")
            start = int(src_parts[0])
            length = int(src_parts[1])
            end = start + length
            # 从源代码内容中提取函数调用的字符串
            func_call_names.append(self.source.content[start:end])
        return func_call_names

    @classmethod
    def _get_sig_to_func_by_contract(cls):
        """
        (类方法) 调用solc编译器获取所有合约的函数签名信息。
        使用 `--combined-json hashes` 选项。

        :return: 包含所有合约函数签名信息的字典，格式: {contract_qname: {'hashes':{func_sig: hash}}}。
        """
        # 根据是否有允许路径构建solc命令
        if cls.allow_paths:
            cmd = 'solc --combined-json hashes %s %s --allow-paths %s' % (cls.remap, cls.parent_filename, cls.allow_paths)
        else:
            cmd = 'solc --combined-json hashes %s %s' % (cls.remap, cls.parent_filename)
        # 执行命令并获取输出
        out = run_command(cmd)
        try:
            # 解析JSON输出
            out = json.loads(out)
            # 返回包含合约签名信息的 'contracts' 部分
            return out['contracts']
        except json.JSONDecodeError:
            print("Error decoding JSON from solc hashes output.")
            print("Output was:", out)
            return {} # 返回空字典表示错误
        except KeyError:
            print("Error: 'contracts' key not found in solc hashes output.")
            print("Output was:", out)
            return {} # 返回空字典表示错误


    @classmethod
    def _load_position_groups_standard_json(cls):
        """
        (类方法) 从标准JSON输出文件加载编译后的位置信息 (asm)。
        标准JSON输出文件通常由外部编译过程生成并命名为 'standard_json_output'。

        :return: 包含所有合约编译信息的字典，格式类似 `solc --combined-json asm` 的 'contracts' 部分。
        """
        try:
            with open('standard_json_output', 'r') as f:
                output = f.read()
            output = json.loads(output)
            # 返回包含合约编译信息的 'contracts' 部分
            return output["contracts"]
        except IOError:
            print("Error: Standard JSON output file 'standard_json_output' not found.")
            return {}
        except json.JSONDecodeError:
            print("Error decoding standard JSON output file.")
            return {}
        except KeyError:
            print("Error: 'contracts' key not found in standard JSON output.")
            return {}

    # 编译生成 asm 和版本信息
    @classmethod
    def _load_position_groups(cls):
        """
        (类方法) 调用solc编译器获取所有合约的编译信息，包括汇编指令和位置映射。
        使用 `--combined-json asm` 选项。

        :return: 包含所有合约编译信息的字典，格式: {contract_qname: {'asm': {...}, ...}}。
        """
        # 根据是否有允许路径构建solc命令
        if cls.allow_paths:
            cmd = "solc --combined-json asm %s %s --allow-paths %s" % (cls.remap, cls.parent_filename, cls.allow_paths)
        else:
            cmd = "solc --combined-json asm %s %s" % (cls.remap, cls.parent_filename)
        # 执行命令并获取输出
        out = run_command(cmd)
        try:
            # 解析JSON输出
            out = json.loads(out)
            # 返回包含合约编译信息的 'contracts' 部分
            return out['contracts']
        except json.JSONDecodeError:
            print("Error decoding JSON from solc asm output.")
            print("Output was:", out)
            return {}
        except KeyError:
            print("Error: 'contracts' key not found in solc asm output.")
            print("Output was:", out)
            return {}

    def _get_positions(self):
        """
        从加载的编译信息中提取当前合约的指令位置列表。
        处理合约代码和可能的库/数据段代码。

        :return: 指令位置信息的列表，每个元素是一个字典，包含 'begin', 'end', 'name', 'value' 等键。
                 如果找不到信息则返回空列表。
        """
        try:
            # 根据输入类型获取合约的汇编信息 (asm)
            if self.input_type == "solidity":
                # 从solc编译结果中获取
                asm = SourceMap.position_groups[self.cname]['asm']['.data']['0']
            else: # standard json or standard json output
                # 从标准JSON输出中获取
                filename, contract_name = self.cname.split(":")
                asm = SourceMap.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0']

            # 提取主代码段的位置信息
            positions = asm['.code']
            # 循环处理可能的嵌套数据段 (例如库代码)
            while True:
                try:
                    # 添加一个None作为分隔符 (可选，取决于后续处理逻辑)
                    positions.append(None)
                    # 将数据段的代码位置信息追加到主列表
                    positions += asm['.data']['0']['.code']
                    # 更新asm指向下一个嵌套的数据段
                    asm = asm['.data']['0']
                except (KeyError, IndexError, TypeError):
                    # 如果没有更多嵌套数据段或数据结构不符合预期，则跳出循环
                    break
            return positions
        except KeyError:
            # 如果找不到当前合约的编译信息
            print("Warning: Could not find assembly information for contract %s" % self.cname)
            return [] # 返回空列表

    def _convert_offset_to_line_column(self, pos):
        """
        将源代码偏移量字典转换为行列信息字典。

        :param pos: 包含 'begin' 和 'end' 偏移量的字典。
        :return: 包含起始和结束行列信息的字典 {'begin': {'line': l, 'column': c}, 'end': {'line': l, 'column': c}}。
                 如果输入偏移量无效，则对应值为None。
        """
        ret = {}
        ret['begin'] = None
        ret['end'] = None
        # 检查偏移量是否有效
        if pos and 'begin' in pos and 'end' in pos and \
           pos['begin'] >= 0 and pos['end'] >= pos['begin']:
            # 转换起始偏移量
            ret['begin'] = self._convert_from_char_pos(pos['begin'])
            # 转换结束偏移量
            ret['end'] = self._convert_from_char_pos(pos['end'])
        return ret

    def _convert_from_char_pos(self, pos):
        """
        将单个字符偏移量转换为行号和列号。

        :param pos: 字符在文件内容中的偏移量 (从0开始)。
        :return: 包含 'line' 和 'column' 的字典 (从0开始计数)。
                 如果偏移量无效或超出范围，返回None。
        """
        if pos < 0 or pos >= len(self.source.content):
            return None # 无效偏移量

        # 使用二分查找在换行符位置列表中找到包含该偏移量的行
        # _find_lower_bound 返回小于等于pos的最大换行符的索引
        line = self._find_lower_bound(pos, self.source.line_break_positions)

        # 计算行号 (从0开始)
        # 如果偏移量正好是换行符，它属于上一行，否则属于下一行
        # 注意：这里的行号计算逻辑可能需要根据具体需求调整，例如是否从1开始计数
        # line = line + 1 # 如果需要从1开始计数

        # 计算列号 (从0开始)
        # 行首的偏移量：如果是第一行(line= -1)，为0；否则为上一行换行符位置+1
        begin_col_offset = 0 if line < 0 else self.source.line_break_positions[line] + 1
        col = pos - begin_col_offset

        # 返回行号和列号 (注意：这里的行号是基于0的索引)
        return {'line': line + 1, 'column': col} # 返回基于0的行号和列号

    def _find_lower_bound(self, target, array):
        """
        在已排序的数组中查找小于或等于目标值的最大元素的索引 (二分查找)。
        用于根据偏移量快速定位行号。

        :param target: 目标值 (字符偏移量)。
        :param array: 已排序的数组 (换行符位置列表)。
        :return: 小于或等于目标值的最大元素的索引。如果目标值小于所有元素，返回-1。
        """
        start = 0
        length = len(array)
        while length > 0:
            half = length >> 1 # 右移一位，相当于除以2取整
            middle = start + half
            if array[middle] <= target:
                # 如果中间值小于等于目标，说明目标在右半部分或就是中间值
                length = length - 1 - half # 调整右半部分的长度
                start = middle + 1 # 移动起始点到中间值的下一个位置
            else:
                # 如果中间值大于目标，说明目标在左半部分
                length = half # 调整左半部分的长度
        # 循环结束后，start 指向第一个大于 target 的元素的位置
        # 因此 start - 1 就是小于或等于 target 的最大元素的索引
        return start - 1

    def get_filename(self):
        """
        从合约限定名中提取文件名。

        :return: 文件名字符串。
        """
        # 合约限定名格式为 "path/to/file.sol:ContractName"
        return self.cname.split(":")[0]
