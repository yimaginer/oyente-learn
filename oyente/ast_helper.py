# 导入外部命令执行函数
from utils import run_command
# 导入AST遍历器类
from ast_walker import AstWalker
# 导入JSON处理模块
import json

class AstHelper:
    """
    Solidity智能合约的抽象语法树(AST)处理辅助类
    用于从编译后的合约中提取结构信息，辅助进行安全分析和漏洞检测
    """
    
    def __init__(self, filename, input_type, remap, allow_paths=""):
        """
        初始化AST辅助类
        
        参数:
        filename - 合约文件名或标准JSON输入文件
        input_type - 输入类型，可以是"solidity"或"standard json"
        remap - 导入重映射参数，用于处理导入路径
        allow_paths - 允许的导入路径，默认为空
        """
        self.input_type = input_type
        self.allow_paths = allow_paths
        
        # 根据不同的输入类型选择不同的处理方式
        if input_type == "solidity":
            self.remap = remap
            # 获取Solidity源文件列表
            self.source_list = self.get_source_list(filename)
        elif input_type == "standard json":
            # 从标准JSON输出获取源文件列表
            self.source_list = self.get_source_list_standard_json(filename)
        else:
            # 如果输入类型不支持则抛出异常
            raise Exception("There is no such type of input")
            
        # 提取所有合约定义
        self.contracts = self.extract_contract_definitions(self.source_list)

    def get_source_list_standard_json(self, filename):
        """
        从标准JSON输出文件中获取源代码列表
        
        参数:
        filename - 标准JSON输入文件名(实际上没有使用)
        
        返回:
        包含所有源代码的字典
        """
        # 打开标准JSON输出文件
        with open('standard_json_output', 'r') as f:
            out = f.read()
        # 解析JSON内容
        out = json.loads(out)
        # 返回sources部分
        return out["sources"]

    def get_source_list(self, filename):
        """
        使用solc编译器获取Solidity源代码列表及其AST
        
        参数:
        filename - Solidity源文件或包含多个文件的目录
        
        返回:
        包含所有源代码AST的字典
        """
        # 构建solc命令，根据是否有允许路径选择不同命令格式
        if self.allow_paths:
            cmd = "solc --combined-json ast %s %s --allow-paths %s" % (self.remap, filename, self.allow_paths)
        else:
            cmd = "solc --combined-json ast %s %s" % (self.remap, filename)
            
        # 执行命令并获取输出
        out = run_command(cmd)
        # 解析JSON格式输出
        out = json.loads(out)
        # 返回sources部分
        return out["sources"]

    def extract_contract_definitions(self, sourcesList):
        """
        从源代码列表中提取所有合约定义
        
        参数:
        sourcesList - 包含源代码及其AST的字典
        
        返回:
        包含按不同方式组织的合约定义的字典:
        - contractsById: 按ID索引的合约
        - contractsByName: 按名称索引的合约
        - sourcesByContract: 按合约ID索引的源文件
        """
        # 初始化返回字典
        ret = {
            "contractsById": {},
            "contractsByName": {},
            "sourcesByContract": {}
        }
        
        # 创建AST遍历器
        walker = AstWalker()
        
        # 遍历所有源文件
        for k in sourcesList:
            # 根据输入类型获取AST
            if self.input_type == "solidity":
                ast = sourcesList[k]["AST"]
            else:
                ast = sourcesList[k]["legacyAST"]
                
            # 存储合约定义节点
            nodes = []
            # 在AST中查找所有ContractDefinition节点
            walker.walk(ast, {"name": "ContractDefinition"}, nodes)
            
            # 处理找到的每个合约定义
            for node in nodes:
                ret["contractsById"][node["id"]] = node
                ret["sourcesByContract"][node["id"]] = k
                ret["contractsByName"][k + ':' + node["attributes"]["name"]] = node
                
        return ret

    def get_linearized_base_contracts(self, id, contractsById):
        """
        获取线性化的基础合约列表（处理继承关系）
        
        参数:
        id - 合约ID
        contractsById - 按ID索引的合约字典
        
        返回:
        线性化的基础合约列表(按继承顺序)
        """
        # 从合约属性中获取线性化的基础合约ID，并映射为实际合约对象
        return map(lambda id: contractsById[id], contractsById[id]["attributes"]["linearizedBaseContracts"])

    def extract_state_definitions(self, c_name):
        """
        提取指定合约的状态变量定义
        
        参数:
        c_name - 合约的完全限定名称(源文件:合约名)
        
        返回:
        状态变量定义列表
        """
        # 获取合约节点
        node = self.contracts["contractsByName"][c_name]
        state_vars = []
        
        if node:
            # 获取线性化的基础合约列表
            base_contracts = self.get_linearized_base_contracts(node["id"], self.contracts["contractsById"])
            base_contracts = list(base_contracts)
            # 反转列表，从最基础的合约开始处理
            base_contracts = list(reversed(base_contracts))
            
            # 遍历所有基础合约(包括当前合约)
            for contract in base_contracts:
                if "children" in contract:
                    # 遍历合约的所有子节点
                    for item in contract["children"]:
                        # 如果是变量声明，则添加到结果列表
                        if item["name"] == "VariableDeclaration":
                            state_vars.append(item)
        return state_vars

    def extract_states_definitions(self):
        """
        提取所有合约的状态变量定义
        
        返回:
        字典，键为合约的完全限定名称，值为状态变量定义列表
        """
        ret = {}
        # 遍历所有合约
        for contract in self.contracts["contractsById"]:
            # 获取合约名称
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            # 获取源文件
            source = self.contracts["sourcesByContract"][contract]
            # 构建完全限定名称
            full_name = source + ":" + name
            # 提取该合约的状态变量定义
            ret[full_name] = self.extract_state_definitions(full_name)
        return ret

    def extract_func_call_definitions(self, c_name):
        """
        提取指定合约中的函数调用定义
        
        参数:
        c_name - 合约的完全限定名称
        
        返回:
        函数调用定义节点列表
        """
        # 获取合约节点
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes = []
        
        if node:
            # 查找所有FunctionCall节点
            walker.walk(node, {"name":  "FunctionCall"}, nodes)
        return nodes

    def extract_func_calls_definitions(self):
        """
        提取所有合约中的函数调用定义
        
        返回:
        字典，键为合约的完全限定名称，值为函数调用定义列表
        """
        ret = {}
        # 遍历所有合约
        for contract in self.contracts["contractsById"]:
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            source = self.contracts["sourcesByContract"][contract]
            full_name = source + ":" + name
            # 提取该合约的函数调用定义
            ret[full_name] = self.extract_func_call_definitions(full_name)
        return ret

    def extract_state_variable_names(self, c_name):
        """
        提取指定合约的状态变量名称
        
        参数:
        c_name - 合约的完全限定名称
        
        返回:
        状态变量名称列表
        """
        # 获取状态变量定义
        state_variables = self.extract_states_definitions()[c_name]
        var_names = []
        # 从定义中提取变量名
        for var_name in state_variables:
            var_names.append(var_name["attributes"]["name"])
        return var_names

    def extract_func_call_srcs(self, c_name):
        """
        提取指定合约中函数调用的源代码位置
        
        参数:
        c_name - 合约的完全限定名称
        
        返回:
        源代码位置字符串列表
        """
        # 获取函数调用定义
        func_calls = self.extract_func_calls_definitions()[c_name]
        func_call_srcs = []
        # 从定义中提取源代码位置
        for func_call in func_calls:
            func_call_srcs.append(func_call["src"])
        return func_call_srcs

    def get_callee_src_pairs(self, c_name):
        """
        获取被调用合约与源代码位置的配对，特别关注delegatecall、call和callcode调用
        这些是智能合约中潜在的高风险操作
        
        参数:
        c_name - 合约的完全限定名称
        
        返回:
        (合约路径, 源代码位置)对的列表
        """
        # 获取合约节点
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes = []
        
        if node:
            # 查找特定的成员调用，即delegatecall、call和callcode
            list_of_attributes = [
                {"attributes": {"member_name": "delegatecall"}},
                {"attributes": {"member_name": "call"}},
                {"attributes": {"member_name": "callcode"}}
            ]
            walker.walk(node, list_of_attributes, nodes)

        callee_src_pairs = []
        # 处理找到的每个节点
        for node in nodes:
            if "children" in node and node["children"]:
                # 获取第一个子节点的类型
                type_of_first_child = node["children"][0]["attributes"]["type"]
                # 如果是合约类型
                if type_of_first_child.split(" ")[0] == "contract":
                    # 提取合约名称
                    contract = type_of_first_child.split(" ")[1]
                    # 查找合约路径
                    contract_path = self._find_contract_path(self.contracts["contractsByName"].keys(), contract)
                    # 添加(合约路径, 源代码位置)对
                    callee_src_pairs.append((contract_path, node["src"]))
        return callee_src_pairs

    def get_func_name_to_params(self, c_name):
        """
        获取函数名到参数的映射
        
        参数:
        c_name - 合约的完全限定名称
        
        返回:
        字典，键为函数名，值为参数列表
        """
        # 获取合约节点
        node = self.contracts['contractsByName'][c_name]
        walker = AstWalker()
        func_def_nodes = []
        
        if node:
            # 查找所有函数定义节点
            walker.walk(node, {'name': 'FunctionDefinition'}, func_def_nodes)

        func_name_to_params = {}
        # 处理每个函数定义
        for func_def_node in func_def_nodes:
            # 获取函数名
            func_name = func_def_node['attributes']['name']
            params_nodes = []
            # 查找参数列表节点
            walker.walk(func_def_node, {'name': 'ParameterList'}, params_nodes)

            # 获取第一个参数列表节点(函数入参)
            params_node = params_nodes[0]
            param_nodes = []
            # 查找变量声明节点(参数)
            walker.walk(params_node, {'name': 'VariableDeclaration'}, param_nodes)

            # 处理每个参数节点
            for param_node in param_nodes:
                # 获取参数名
                var_name = param_node['attributes']['name']
                # 获取类型名称
                type_name = param_node['children'][0]['name']
                
                # 根据不同类型处理参数
                if type_name == 'ArrayTypeName':
                    # 处理数组类型
                    literal_nodes = []
                    walker.walk(param_node, {'name': 'Literal'}, literal_nodes)
                    # 确定数组大小
                    if literal_nodes:
                        array_size = int(literal_nodes[0]['attributes']['value'])
                    else:
                        array_size = 1
                    param = {'name': var_name, 'type': type_name, 'value': array_size}
                elif type_name == 'ElementaryTypeName':
                    # 处理基本类型
                    param = {'name': var_name, 'type': type_name}
                else:
                    # 处理其他类型
                    param = {'name': var_name, 'type': type_name}

                # 将参数添加到对应函数的参数列表中
                if func_name not in func_name_to_params:
                    func_name_to_params[func_name] = [param]
                else:
                    func_name_to_params[func_name].append(param)
                    
        return func_name_to_params

    def _find_contract_path(self, contract_paths, contract):
        """
        查找合约的完全路径
        
        参数:
        contract_paths - 合约路径列表
        contract - 合约名称
        
        返回:
        合约的完全路径，如果没找到则返回空字符串
        """
        # 遍历所有合约路径
        for path in contract_paths:
            # 提取合约名
            cname = path.split(":")[-1]
            # 如果找到匹配的合约名
            if contract == cname:
                return path
        # 没找到则返回空字符串
        return ""