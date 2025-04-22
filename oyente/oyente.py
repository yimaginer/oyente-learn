#!/usr/bin/env python
# 整个项目的函数入口，主要承担着接受参数，存储变量以及调用不同函数的作用

import os
import re
import six
import json
import symExec
import logging
import requests
import argparse
import subprocess
import global_params
from utils import run_command
from input_helper import InputHelper

def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def compare_versions(version1, version2):
    def normalize(v):
        return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]
    version1 = normalize(version1)
    version2 = normalize(version2)
    if six.PY2:
        return cmp(version1, version2)
    else:
        return (version1 > version2) - (version1 < version2)

def has_dependencies_installed():
    try:
        import z3
        import z3.z3util
        z3_version =  z3.get_version_string()
        tested_z3_version = '4.5.1'
        if compare_versions(z3_version, tested_z3_version) > 0:
            logging.warning("You are using an untested version of z3. %s is the officially tested version" % tested_z3_version)
    except e:
        logging.critical(e)
        logging.critical("Z3 is not available. Please install z3 from https://github.com/Z3Prover/z3.")
        return False

    if not cmd_exists("evm"):
        logging.critical("Please install evm from go-ethereum and make sure it is in the path.")
        return False
    else:
        cmd = "evm --version"
        out = run_command(cmd).strip()
        evm_version = re.findall(r"evm version (\d*.\d*.\d*)", out)[0]
        tested_evm_version = '1.7.3'
        if compare_versions(evm_version, tested_evm_version) > 0:
            logging.warning("You are using evm version %s. The supported version is %s" % (evm_version, tested_evm_version))

    if not cmd_exists("solc"):
        logging.critical("solc is missing. Please install the solidity compiler and make sure solc is in the path.")
        return False
    else:
        cmd = "solc --version"
        out = run_command(cmd).strip()
        solc_version = re.findall(r"Version: (\d*.\d*.\d*)", out)[0]
        tested_solc_version = '0.4.19'
        if compare_versions(solc_version, tested_solc_version) > 0:
            logging.warning("You are using solc version %s, The latest supported version is %s" % (solc_version, tested_solc_version))

    return True


def run_solidity_analysis(inputs):
    """
    对准备好的Solidity合约输入列表进行符号执行分析。

    该函数遍历由InputHelper生成的输入列表，对每个合约调用核心的符号执行引擎(symExec.run)，
    并收集和组织分析结果。

    参数:
    inputs (list): 一个字典列表，每个字典代表一个要分析的合约，
                   包含分析所需的信息，例如：
                   - 'contract': 合约的完全限定名称 (e.g., "path/to/file.sol:MyContract")
                   - 'disasm_file': 反汇编后的EVM字节码文件路径
                   - 'source_map': SourceMap对象，用于字节码到源代码的映射
                   - 'source_file': 原始Solidity源文件路径
                   - 'c_source': 合约所属的源文件路径
                   - 'c_name': 合约的名称

    返回:
    tuple: 包含两个元素的元组:
           - results (dict): 一个嵌套字典，存储所有合约的分析结果。
                             结构: {source_file_path: {contract_name: analysis_result}}
           - exit_code (int): 最终的退出代码。如果任何一个合约分析失败，则为1，否则为0。
    """
    # 初始化用于存储所有分析结果的字典
    results = {}
    # 初始化退出代码，默认为0 (表示成功)
    exit_code = 0

    # 遍历InputHelper准备好的每个合约输入项
    for inp in inputs:
        # 记录日志，标明当前正在分析哪个合约
        logging.info("contract %s:", inp['contract'])

        # 调用核心符号执行引擎 symExec.run 进行分析
        # 传入反汇编文件路径、源代码映射对象和源文件路径
        result, return_code = symExec.run(
            disasm_file=inp['disasm_file'],
            source_map=inp['source_map'],
            source_file=inp['source']
        )

        # 尝试将当前合约的分析结果 (result) 添加到总结果字典 (results) 中
        # 使用源文件路径和合约名作为键进行嵌套存储
        try:
            c_source = inp['c_source'] # 获取源文件路径
            c_name = inp['c_name']     # 获取合约名称
            # 将结果存入 results[源文件路径][合约名]
            results[c_source][c_name] = result
        except KeyError:
            # 如果这是该源文件的第一个合约，results[c_source] 还不存在
            # 需要先创建内部字典
            results[c_source] = {c_name: result}

        # 检查当前合约的分析返回代码 (return_code)
        # 如果 return_code 为 1，表示该合约分析过程中出现错误或检测到严重问题
        if return_code == 1:
            # 将整体退出代码设置为 1，表示整个分析过程至少有一个失败
            exit_code = 1

    # 返回包含所有分析结果的字典和最终的退出代码
    return results, exit_code


# 分析 solidity 合约
# analyze_solidity 函数的主要工作为:
# 1. 主要做的就是根据输入的类型，来获得我们想要的 helper。
# 2. 通过 helper 的 get_inputs() 函数，我们能够得到 inputs 变量。
# 3. 将 input 变量传入 run_solidity_analysis() 函数，就能得到我们想要的结果。
def analyze_solidity(input_type='solidity'):
    global args

    if input_type == 'solidity':
        helper = InputHelper(InputHelper.SOLIDITY, source=args.source, evm=args.evm, compilation_err=args.compilation_error, root_path=args.root_path, remap=args.remap, allow_paths=args.allow_paths)
    elif input_type == 'standard_json':
        helper = InputHelper(InputHelper.STANDARD_JSON, source=args.source, evm=args.evm, allow_paths=args.allow_paths)
    elif input_type == 'standard_json_output':
        helper = InputHelper(InputHelper.STANDARD_JSON_OUTPUT, source=args.source, evm=args.evm)
    
    # 获取合约相关信息，用于分析
    inputs = helper.get_inputs(global_params.TARGET_CONTRACTS)
    results, exit_code = run_solidity_analysis(inputs)

    helper.rm_tmp_files()
    if global_params.WEB:
        six.print_(json.dumps(results))
    return exit_code

# main函数主要工作为:
# 1. 实例化创建解析器，解析命令行传入的参数变量，参数变量部分存储于 global_params.py 中。
# 2. add_argument 可以对应 args 内第二个参数，当使用 python3 oyente.py -s *.sol 指令时，args.source 的值对应的是合约文件的地址。
# 3. 由于没有别的参数，将直接调用 exit_code = analyze_solidity()
def main():
    # TODO: Implement -o switch.

    global args

    # argparse 是一个 Python 模块：命令行选项、参数和子命令解析器。
    # 主要有三个步骤：
    # 创建 ArgumentParser() 对象
    # 调用 add_argument() 方法添加参数
    # 使用 parse_args() 解析添加的参数
    parser = argparse.ArgumentParser()
    # ArgumentParser.add_mutually_exclusive_group(required=True):创建一个互斥的组, argparse 将会确保互斥组中只有一个参数在命令行中可用。
    # 该方法也接受一个 required 参数，表示在互斥组中至少有一个参数是需要的。该对象和 ArgumentParser 对象类似
    group = parser.add_mutually_exclusive_group(required=True)

    # 通过调用 add_argument() 方法给 ArgumentParser 对象添加程序所需的参数信息
    group.add_argument("-s",  "--source",    type=str, help="local source file name. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin.")
    group.add_argument("-ru", "--remoteURL", type=str, help="Get contract from remote URL. Solidity by default. Use -b to process evm instead.", dest="remote_URL")

    parser.add_argument("-cnames", "--target-contracts", type=str, nargs="+", help="The name of targeted contracts. If specified, only the specified contracts in the source code will be processed. By default, all contracts in Solidity code are processed.")
    
    parser.add_argument("--version", action="version", version="oyente version 0.2.7 - Commonwealth")

    parser.add_argument("-rmp", "--remap",          help="Remap directory paths", action="store", type=str)
    parser.add_argument("-t",   "--timeout",        help="Timeout for Z3 in ms.", action="store", type=int)
    parser.add_argument("-gl",  "--gaslimit",       help="Limit Gas", action="store", dest="gas_limit", type=int)
    parser.add_argument("-rp",   "--root-path",     help="Root directory path used for the online version", action="store", dest="root_path", type=str)
    parser.add_argument("-ll",  "--looplimit",      help="Limit number of loops", action="store", dest="loop_limit", type=int)
    parser.add_argument("-dl",  "--depthlimit",     help="Limit DFS depth", action="store", dest="depth_limit", type=int)
    parser.add_argument("-ap",  "--allow-paths",    help="Allow a given path for imports", action="store", dest="allow_paths", type=str)
    parser.add_argument("-glt", "--global-timeout", help="Timeout for symbolic execution", action="store", dest="global_timeout", type=int)

    parser.add_argument( "-e",   "--evm",                    help="Do not remove the .evm file.", action="store_true")
    parser.add_argument( "-w",   "--web",                    help="Run Oyente for web service", action="store_true")
    parser.add_argument( "-j",   "--json",                   help="Redirect results to a json file.", action="store_true")
    parser.add_argument( "-p",   "--paths",                  help="Print path condition information.", action="store_true")
    parser.add_argument( "-db",  "--debug",                  help="Display debug information", action="store_true")
    parser.add_argument( "-st",  "--state",                  help="Get input state from state.json", action="store_true")
    parser.add_argument( "-r",   "--report",                 help="Create .report file.", action="store_true")
    parser.add_argument( "-v",   "--verbose",                help="Verbose output, print everything.", action="store_true")
    parser.add_argument( "-pl",  "--parallel",               help="Run Oyente in parallel. Note: The performance may depend on the contract", action="store_true")
    parser.add_argument( "-b",   "--bytecode",               help="read bytecode in source instead of solidity file.", action="store_true")
    parser.add_argument( "-a",   "--assertion",              help="Check assertion failures.", action="store_true")
    parser.add_argument( "-sj",  "--standard-json",          help="Support Standard JSON input", action="store_true")
    parser.add_argument( "-gb",  "--globalblockchain",       help="Integrate with the global ethereum blockchain", action="store_true")
    parser.add_argument( "-ce",  "--compilation-error",      help="Display compilation errors", action="store_true")
    parser.add_argument( "-gtc", "--generate-test-cases",    help="Generate test cases each branch of symbolic execution tree", action="store_true")
    parser.add_argument( "-sjo", "--standard-json-output",   help="Support Standard JSON output", action="store_true")

    # 通过 parse_args() 方法解析参数
    # 在脚本中，通常 parse_args() 会被不带参数调用，而 ArgumentParser 将自动从 sys.argv 中确定命令行参数。
    args = parser.parse_args()

    if args.root_path:
        if args.root_path[-1] != '/':
            args.root_path += '/'
    else:
        args.root_path = ""

    args.remap = args.remap if args.remap else ""
    args.allow_paths = args.allow_paths if args.allow_paths else ""

    if args.timeout:
        global_params.TIMEOUT = args.timeout

    logging.basicConfig()
    rootLogger = logging.getLogger(None)
    
    if args.verbose:
        rootLogger.setLevel(level=logging.DEBUG)
    else:
        rootLogger.setLevel(level=logging.INFO)

    global_params.PRINT_PATHS = 1 if args.paths else 0
    global_params.REPORT_MODE = 1 if args.report else 0
    global_params.USE_GLOBAL_BLOCKCHAIN = 1 if args.globalblockchain else 0
    global_params.INPUT_STATE = 1 if args.state else 0
    global_params.WEB = 1 if args.web else 0
    global_params.STORE_RESULT = 1 if args.json else 0
    global_params.CHECK_ASSERTIONS = 1 if args.assertion else 0
    global_params.DEBUG_MODE = 1 if args.debug else 0
    global_params.GENERATE_TEST_CASES = 1 if args.generate_test_cases else 0
    global_params.PARALLEL = 1 if args.parallel else 0
    
    if args.target_contracts and args.bytecode:
        parser.error('Targeted contracts cannot be specifed when the bytecode is provided (Instead of Solidity source code).')
    global_params.TARGET_CONTRACTS = args.target_contracts
    
    if args.depth_limit:
        global_params.DEPTH_LIMIT = args.depth_limit
    if args.gas_limit:
        global_params.GAS_LIMIT = args.gas_limit
    if args.loop_limit:
        global_params.LOOP_LIMIT = args.loop_limit
    if global_params.WEB:
        if args.global_timeout and args.global_timeout < global_params.GLOBAL_TIMEOUT:
            global_params.GLOBAL_TIMEOUT = args.global_timeout
    else:
        if args.global_timeout:
            global_params.GLOBAL_TIMEOUT = args.global_timeout

    if not has_dependencies_installed():
        return

    if args.remote_URL:
        r = requests.get(args.remote_URL)
        code = r.text
        filename = "remote_contract.evm" if args.bytecode else "remote_contract.sol"
        args.source = filename
        with open(filename, 'w') as f:
            f.write(code)

    exit_code = 0
    if args.bytecode:
        exit_code = analyze_bytecode()
    elif args.standard_json:
        exit_code = analyze_solidity(input_type='standard_json')
    elif args.standard_json_output:
        exit_code = analyze_solidity(input_type='standard_json_output')
    else:
        exit_code = analyze_solidity()

    exit(exit_code)

if __name__ == '__main__':
    main()
