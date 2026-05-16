import argparse
import datetime
import os
import re
import struct
import sys
from typing import Literal
from loguru import logger

__author__ = 'castimage'
__version__ = '0.4.0-dev'

def func_timeit(func):
    """
    装饰器：自动记录函数执行时间
    """

    def wrapper(*args, **kwargs):
        start_time = datetime.datetime.now()
        result = func(*args, **kwargs)
        end_time = datetime.datetime.now()
        logger.debug(f'{func.__name__} 执行时间: {end_time - start_time}')
        return result

    return wrapper

def log_method_call(level: Literal['debug', 'info', 'success', 'warning', 'error'] = 'debug'):
    """
    装饰器：自动记录方法调用的日志
    """

    def decorator(func):
        def wrapper(self, *args, **kwargs):
            func_name = func.__name__
            args_str = ', '.join([repr(arg) for arg in args])
            kwargs_str = ', '.join([f'{k}={repr(v)}' for k, v in kwargs.items()])
            params_str = ', '.join(filter(None, [args_str, kwargs_str]))

            getattr(logger, level)(f'调用方法 {func_name} - ' + (f'参数: ({params_str})' if params_str else '无参数'))

            try:
                result = func(self, *args, **kwargs)
                logger.debug(f'方法 {func_name} 执行完成, 返回结果: {result}')
                return result
            except Exception as e:
                logger.error(f'方法 {func_name} 执行异常: {str(e)}')
                raise

        return wrapper

    return decorator


class T2kSCompilerException(Exception):
    """
    编译器异常基类
    """

    pass


class T2kSLocationOutOfRangeException(T2kSCompilerException):
    """
    地址超出范围异常
    """

    def __init__(self, address, start, end):
        super().__init__(f'地址 \'{hex(address)}\' 超出范围 {hex(start)} - {hex(end)} !')


class T2kSSyntaxError(T2kSCompilerException):
    """
    语法错误类
    """

    def __init__(self, msg=''):
        super().__init__(f'语法错误{': ' if msg != '' else ''}{msg}{' !' if msg != '' else '!'}')


class T2kSJumpError(T2kSCompilerException):
    """
    跳转错误类
    """

    def __init__(self, source_addr, target_addr):
        super().__init__(
            f'从 \'{source_addr}\' 跳转到地址 \'{target_addr}\' 无效，超出偏移量范围！需使用jmpa进行跳转，请检查相应代码！')


class T2kSLabelRepeatError(T2kSCompilerException):
    """
    标签重复异常类
    """

    def __init__(self, label):
        super().__init__(f'标签 \'{label}\' 重复!')


class T2kSLabelNotFoundError(T2kSCompilerException):
    """
    标签未找到异常类
    """

    def __init__(self, label):
        super().__init__(f'标签 \'{label}\' 未找到！')


class MemRangeManager:
    """
    内存范围管理器
    """

    def __init__(self, max_range=(0x0000, 0xFFFF), preferred_range=None, allow_non_user_area: bool = False):
        self.preferred_range = preferred_range if preferred_range else (0x2000, 0x25FF)
        self.ranges = []
        self.max_range = max_range
        self.allow_non_user_area = allow_non_user_area

    @log_method_call()
    def add_range(self, start: int, end: int) -> None:
        """
        添加内存范围
        :param start: 起始位置
        :param end: 结束位置
        """

        if start < self.max_range[0] or end > self.max_range[1]:
            logger.error(f'地址超出范围: 地址 {hex(start)}-{hex(end)} 超出范围 {hex(self.max_range[0])}-{hex(self.max_range[1])}')
            raise T2kSLocationOutOfRangeException(
                start if start < self.max_range[0] else end,
                hex(self.max_range[0]),
                hex(self.max_range[1])
            )

        if not self.allow_non_user_area and start < self.preferred_range[0] or end > self.preferred_range[1]:
            logger.error(f'地址超出范围: 地址 {hex(start)}-{hex(end)} 非用户区')
            raise ValueError(f'地址 {hex(start)}-{hex(end)} 非用户区')

        self.ranges.append((start, end))
        self.ranges.sort()

    def get_boundary(self) -> tuple[int, int]:
        """
        获取内存范围
        :return: (起始位置, 结束位置)
        """
        return self.ranges[0][0], max(m[1] for m in self.ranges)


class T2kSCompiler:
    """
    TEC2000 Simulator 编译器
    """
    def __init__(self, allow_non_user_area: bool = None):
        self.allow_non_user_area = False if not allow_non_user_area else allow_non_user_area
        self.labels = {}

    # 参数语法正则
    syntax_arg_regex = {
        'tag_goto': r'[0-9a-fA-F]{1,4}:',  # 跳转标签类型
        'tag_label': r'tag-[0-9a-zA-Z_]+:',  # 标签类型
        'params': {
            'register': r'[rR](?:1[0-5]|[0-3 6-9])',  # 寄存器类型
            'memory': r'\[(?:[rR](?:1[0-5]|[0-3 6-9]))\]',  # 内存类型
            'io_port': r'[0-9][0-9]|[0-9]',  # IO端口类型
            'address': r'[0-9a-fA-F]{1,4}',  # 地址类型
            'immediate': r'[0-9a-fA-F]{1,4}',  # 立即数类型
            'tag_label': r'tag-[0-9a-zA-Z_]+',  # 标签类型
            'offset_jump': r'(?:\+[0-7][0-9a-fA-F]|\+80|\+[0-9a-fA-F]|-[0-7][0-9a-fA-F]|-[0-9a-fA-F])'  # 偏移跳转类型
        }
    }

    # 汇编指令定义: (操作码对应机器码，指令字节数，参数类型...)
    assembly_code = {
        'add': (0x0, 2, 'register', 'register'),  # ADD R1, R2 - 寄存器加法
        'sub': (0x1, 2, 'register', 'register'),  # SUB R1, R2 - 寄存器减法
        'and': (0x2, 2, 'register', 'register'),  # AND R1, R2 - 寄存器按位与
        'cmp': (0x3, 2, 'register', 'register'),  # CMP R1, R2 - 比较寄存器
        'xor': (0x4, 2, 'register', 'register'),  # XOR R1, R2 - 寄存器异或
        'test': (0x5, 2, 'register', 'register'),  # TEST R1, R2 - 测试寄存器
        'or': (0x6, 2, 'register', 'register'),  # OR R1, R2 - 寄存器按位或
        'mvrr': (0x7, 2, 'register', 'register'),  # MVRR R1, R2 - 寄存器间移动数据
        'dec': (0x8, 2, 'register'),  # DEC R1 - 寄存器减一
        'inc': (0x9, 2, 'register'),  # INC R1 - 寄存器加一
        'shl': (0xa, 2, 'register'),  # SHL R1 - 寄存器左移一位
        'shr': (0xb, 2, 'register'),  # SHR R1 - 寄存器右移一位
        'jr': (0x41, 2, ['address', 'tag_label', 'offset_jump']),  # JR addr - 相对跳转
        'jrc': (0x44, 2, ['address', 'tag_label', 'offset_jump']),  # JRC addr - 进位时相对跳转
        'jrnc': (0x45, 2, ['address', 'tag_label', 'offset_jump']),  # JRNC addr - 无进位时相对跳转
        'jrz': (0x46, 2, ['address', 'tag_label', 'offset_jump']),  # JRZ addr - 零标志置位时相对跳转
        'jrnz': (0x47, 2, ['address', 'tag_label', 'offset_jump']),  # JRNZ addr - 零标志清零时相对跳转
        'jmpa': (0x8000, 4, ['address', 'tag_label', 'offset_jump']),  # JMPA addr - 绝对跳转
        'ldrr': (0x81, 2, 'register', 'memory'),  # LDRR R1, [R2] - 从内存加载到寄存器
        'in': (0x82, 2, 'io_port'),  # IN port - 从IO端口读取
        'strr': (0x83, 2, 'memory', 'register'),  # STRR [R1], R2 - 存储寄存器到内存
        'pshf': (0x8400, 2),  # PSHF - 压入标志位
        'push': (0x85, 2, 'register'),  # PUSH R1 - 压入寄存器
        'out': (0x86, 2, 'io_port'),  # OUT port - 输出到IO端口
        'pop': (0x87, 2, 'register'),  # POP R1 - 弹出到寄存器
        'mvrd': (0x88, 4, 'register', ['immediate', 'tag_label']),  # MVRD R1, DATA - 移动立即数到寄存器
        'popf': (0x8c00, 2),  # POPF - 弹出标志位
        'ret': (0x8f00, 2),  # RET - 返回
        'cala': (0xce00, 4, ['address', 'tag_label', 'offset_jump']),  # CALA addr - 调用绝对地址

        # 监控程序可调用子程序
        'inch': (0xce000524, 4),  # INCH - 输入字符
        'out1ch': (0xce00056b, 4),  # OUT1CH - 输出字符
        'upcase': (0xce0005e9, 4),  # UPCASE - 大写转换
        'indat': (0xce0005f7, 4),  # INDAT - 输入数据
        'wstr1ch': (0xce00057f, 4),  # 输出字符串
        'inline': (0xce000589, 4),  # 输入一行数据
        'shdw': (0xce000654, 4),  # r0 > 8bit
        'shd4': (0xce000656, 4),  # r0 > 4bit
        'shup': (0xce00065b, 4),  # r0 < 8bit
        'shu4': (0xce00065d, 4),  # r0 < 4bit
        'numasc': (0xce000664, 4),  # 输出R15的十六进制数字

        # 自设命令
        'dw': (0xffff, 2, ['immediate', 'tag_label']),  # DW DATA - 直接操作2字节数据
    }

    # 需计算偏移的指令
    op_offset = ['jr', 'jrc', 'jrnc', 'jrz', 'jrnz']
    # p0格式的指令
    op_p0 = ['dec', 'inc', 'shl', 'shr', 'pop', 'mvrd']
    # 0p格式的指令
    op_0p = ["push"]

    @log_method_call()
    def validate_syntax(self, line: str) -> bool:
        """
        语法检查
        :param line: 待检查的行
        :return: 检查结果
        """

        # 移除注释
        line = line.split('#')[0].strip()

        # 空行跳过
        if line == '':
            return True

        # 是否为跳转标签
        if re.fullmatch(self.syntax_arg_regex.get('tag_goto'), line) is not None:
            logger.debug(f'跳转指令 \'{line}\' ')
            return True

        # 是否为普通标签
        if re.fullmatch(self.syntax_arg_regex.get('tag_label'), line) is not None:
            logger.debug(f'普通标签 \'{line}\' ')
            return True

        lines = line.split(" ")
        lines[0] = str(lines[0]).lower()
        line = f"{lines[0]}{line[len(lines[0]):].split("#")[0]}".strip()

        # 指令是否存在
        if lines[0] not in self.assembly_code.keys():
            logger.error(f'指令 \'{lines[0]}\' 不存在')
            return False

        # 参数数量是否正确
        if len(lines) != len(self.assembly_code.get(lines[0])) - 1:
            logger.error(f'指令 \'{lines[0]}\' 参数数量错误')
            return False

        if len(lines) == 1:
            return True

        # 参数格式是否正确
        if not re.fullmatch(
                rf'(?:{lines[0].lower()}|{lines[0].upper()}) {', '.join((self.syntax_arg_regex.get('params').get(param) if isinstance(param, str) else f'(?:{'|'.join(self.syntax_arg_regex.get('params').get(p) for p in param)})') for param in self.assembly_code.get(lines[0])[2:])}',
                line
        ):
            logger.error(f'指令 \'{lines[0]}\' 参数格式错误')
            return False

        return True

    @log_method_call()
    def check_input_file(self, filepath: str) -> None:
        """
        检查输入文件
        :param filepath: 输入文件路径
        """

        if not os.path.exists(filepath):
            logger.error(f'文件不存在: 文件 \'{filepath}\' 不存在')
            raise FileNotFoundError(f'文件 \'{filepath}\' 不存在')

        if os.path.isdir(filepath):
            logger.error(f'路径错误: 路径 \'{filepath}\' 错误，请检查路径')
            raise IsADirectoryError(f'路径 \'{filepath}\' 是一个目录，非文件')


        logger.info(f'正在检查 {os.path.basename(filepath)} 语法...')

        is_syntax_valid = True
        with open(filepath, 'r', encoding='utf-8') as input_file:
            lline = 1
            for line in input_file.readlines():
                line = line.strip()
                if line == '':
                    lline += 1
                    continue
                if self.validate_syntax(line):
                    logger.debug(f'line {lline} - 语法正确: {line}')
                else:
                    logger.error(f'line {lline} - 语法错误!: {line}')
                    is_syntax_valid = False
                lline += 1
        if is_syntax_valid:
            logger.info('语法检查结束，通过检查！')
        else:
            logger.error('语法检查结束，未通过检查！')
            raise T2kSSyntaxError()

    @log_method_call()
    def param2code(self, param: str, param_type: str, is_offset: bool = False, is_p0: bool = False, is_0p: bool = False, original_address: int = 0x0) -> str:
        """
        参数转换为机器码
        :param param: 参数
        :param param_type: 参数类型
        :param is_offset: 是否为偏移量
        :param is_p0: 是否为p0格式
        :param is_0p: 是否为0p格式
        :param original_address: 原始地址
        :return: 机器码
        """

        if param_type == 'tag_label' and param not in self.labels:
            logger.error(f'标签 \'{param}\' 未定义!')
            raise T2kSLabelNotFoundError(param)

        res = None
        if param_type == 'register':
            r = hex(int(param[1:]))[2:]
            if is_p0:
                res = f'{r}0'
            elif is_0p:
                res = f'0{r}'
            else:
                res = r
        elif param_type == 'memory':
            res = hex(int(param[1:]))[2:]
        elif param_type == 'io_port':
            res = str(int(param))
        elif param_type == 'address':
            res = hex(int(param, 16))[2:].zfill(4) if not is_offset else hex(int(param, 16) - original_address - 1)[2:].zfill(2) if int(param, 16) > original_address else hex(int(param, 16) + 0xFF - original_address)[2:].zfill(2)
        elif param_type == 'immediate':
            res = hex(int(param, 16))[2:].zfill(4)
        elif param_type == 'tag_label':
            res = hex(int(self.labels.get(param)))[2:].zfill(4) if not is_offset else hex(int(self.labels.get(param)) - original_address - 1)[2:].zfill(2) if int(self.labels.get(param)) > original_address else hex(int(self.labels.get(param)) + 0xFF - original_address)[2:].zfill(2)
        elif param_type == 'offset_jump':
            res = hex(original_address + int(param, 16))[2:].zfill(4) if not is_offset else hex(int(param, 16) - 1)[2:].zfill(2) if int(param, 16) > 0 else hex(int(param, 16) + 0xFF)[2:].zfill(2)
        else:
            logger.error(f'参数类型 \'{param_type}\' 不存在')
            raise T2kSCompilerException(param_type)
        
        return res

    @log_method_call()
    def process_header(self, file_handler, boundary: tuple, flag: int = 0x01) -> None:
        """
        处理文件头
        :param file_handler: 文件句柄
        :param boundary: 参数边界
        :param flag: 文件头标志
        """

        if not file_handler or not boundary:
            logger.warning('有传入参数为空，忽略处理')
            return

        # 文件头格式：flag(1字节) + start_addr(2字节) + length(2字节)，小端序
        file_handler.write(struct.pack('<BHH', flag, boundary[0], boundary[1] - boundary[0]))

        logger.success('文件头写入完成')

    @log_method_call()
    def process_body(self, file_handler, prep: list, boundary: tuple) -> None:
        """
        处理程序体
        :param file_handler: 文件句柄
        :param prep: 预处理数据
        :param boundary: 参数边界
        """

        if not file_handler or not prep or not boundary:
            logger.warning('有传入参数为空，忽略处理')
            return

        logger.info('正在计算需写入内存...')

        # 初始化需写入内存数组
        mem = [0x0 for _ in range(boundary[1] - boundary[0])]
        for data in prep:
            now = list(dict(data).keys())[0]
            for line in dict(data).get(now):

                # 检查偏移量是否超出合法范围
                if line[0] in self.op_offset:
                    is_addr = re.fullmatch(self.syntax_arg_regex.get('params').get('address'), line[1]) is not None
                    is_offset_jump = re.fullmatch(self.syntax_arg_regex.get('params').get('offset_jump'), line[1]) is not None

                    if not is_addr and not is_offset_jump and line[1] not in self.labels:
                        logger.error(f'标签 \'{line[1]}\' 未定义！')
                        raise T2kSLabelNotFoundError(line[1])

                    if is_offset_jump:
                        offset = int(line[1], 16)
                        addr = int(now, 16) + offset
                    else:
                        addr = int(line[1], 16) if is_addr else self.labels.get(line[1])
                        offset = addr - int(now, 16)

                    if not -0x7F <= offset <= 0x80:
                        raise T2kSJumpError(now, hex(addr) if is_addr else hex(self.labels.get(line[1])))

                # 获取指令定义
                config = self.assembly_code.get(str(line[0]).lower())

                # 获取指令参数机器码列表
                params = [
                    self.param2code(
                        line[i + 1],
                        config[2 + i] if isinstance(config[2 + i], str) else [param_type for param_type in config[2 + i] if re.fullmatch(self.syntax_arg_regex.get('params').get(param_type), line[i + 1].lower())][0],
                        line[0] in self.op_offset,
                        line[0] in self.op_p0,
                        line[0] in self.op_0p,
                        int(now, 16)
                    ) for i in range(len(config[2:]))
                ]
                op_base = hex(config[0])[2:]

                # 合并生成单条指令完整机器码
                op = hex(int(f'"0x{op_base}{''.join(params)}"', 16))[2:].zfill(4)

                op = op[4:] if str(line[0]).lower() == 'dw' else op

                # 计算内存索引并写入
                mem_index = int(now, 16) - boundary[0]
                if config[1] == 2:  # 8位指令(1字)
                    mem[mem_index] = int(op, 16)
                    now = hex(int(now, 16) + 1)
                else:  # 16位指令(2字)
                    mem[mem_index] = int(op[:4], 16)
                    mem[mem_index + 1] = int(op[4:], 16)
                    now = hex(int(now, 16) + 2)

        logger.debug(f'已计算出需写入内存: {[hex(byte)[2:].zfill(4).upper() for byte in mem]}')
        logger.info('正在写入文件...')

        #将机器码写入文件
        for byte in mem:
            file_handler.write(struct.pack('>H', byte))

        logger.success('写入完成！')

    @log_method_call()
    def pre_process_file(self, input_file: str, start_location: int) -> tuple[list, tuple]:
        """
        预处理文件
        :param input_file: 输入文件位置
        :param start_location: 起始位置
        :return: 预处理数据，边界元组(起始地址, 结束地址)
        """

        start = start_location
        now = start
        prep = []
        block = []
        mem_range_manager = MemRangeManager()

        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                # 移除注释
                line = line.split('#')[0].strip()
                if line == '':
                    continue

                #移除不需要的符号
                param = re.sub(r'[\[\],:]', '', line).split(' ')

                # 如果是跳转标签则存储老块并创建新块
                if re.fullmatch(self.syntax_arg_regex.get('tag_goto'), line) is not None:
                    # 块大小为空时不做存储
                    prep.append({hex(start): block}) if len(block) > 0 else None
                    mem_range_manager.add_range(start, now) if len(block) > 0 else None

                    now = start = int(param[0], 16)
                    block = []

                # 如果是tag标签则存储至全局字典
                elif re.fullmatch(self.syntax_arg_regex.get('tag_label'), line) is not None:
                    if param[0] in self.labels:
                        logger.error(f'标签 \'{param[0]}\' 重复!')
                        raise T2kSLabelRepeatError(param[0])

                    self.labels[param[0]] = now

                # 否则为当前块中的普通指令
                else:
                    block.append(param)
                    now += int(self.assembly_code.get(str(param[0]).lower())[1] / 2)

        # 处理最后一块
        if len(block) > 0:
            prep.append({hex(start): block})
            mem_range_manager.add_range(start, now)

        logger.success('文件预处理完成!')
        return prep, mem_range_manager.get_boundary()

    @log_method_call()
    @func_timeit
    def compile_file(self, input_file: str, output_file: str = None, start_location: int = 0x2000) -> None:
        """
        编译二进制文件
        :param input_file: 输入文件位置
        :param output_file: 输出文件位置
        :param start_location: 程序起始位置
        """

        self.labels = {}

        # 检查输入文件，有异常则直接中止
        self.check_input_file(input_file)
        # 确定输出文件路径
        if output_file is None:
            # 当程序被打包为exe运行时，__file__会指向临时目录，所以需要使用sys.argv[0]获取真实路径
            if getattr(sys, 'frozen', False):
                # 程序作为exe运行
                script_dir = str(os.path.dirname(os.path.abspath(sys.argv[0])))
            else:
                # 程序作为脚本运行
                script_dir = str(os.path.dirname(__file__))
            output_file = str(os.path.join(script_dir, os.path.basename(input_file).split('.')[0] + '.cod'))
        # 预处理文件以获得预处理数据与边界
        prep, boundary = self.pre_process_file(input_file, start_location)

        logger.info('开始文件编译...')

        with open(output_file, 'wb') as f:
            self.process_header(f, boundary)
            self.process_body(f, prep, boundary)

        logger.success(f'文件编译完成！文件存储位置: {os.path.abspath(output_file)}')


def parse_arguments():
    """
    解析命令行参数
    """

    parser = argparse.ArgumentParser(description='TEC2000 Simulator 编译器 - python3 ver.')

    parser.add_argument('-i', '--input-file',
                        required=True,
                        help='需要编译的文件位置'
                        )
    parser.add_argument('-o', '--output-file',
                        help='编译后的输出文件位置，不指定则以输入文件同名输出至脚本文件所在文件夹'
                        )
    parser.add_argument('-s', '--start_location',
                        type=lambda x: int(x, 16),
                        default=0x2000,
                        help='程序初始写入位置，默认为0x2000'
                        )
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='显示详细编译信息，与 -q 参数互斥'
                        )
    parser.add_argument('-q', '--quite',
                        action='store_true',
                        help='静默编译，仅当出现错误时输出，与 -v 参数互斥'
                        )
    parser.add_argument('--allow_non_user_area',
                        action='store_true',
                        help='允许非用户区写入，默认不允许'
                        )

    return parser.parse_args()

def main():
    """
    主函数
    """

    try:
        args = parse_arguments()

        if args.verbose and args.quite:
            logger.error('-v 和 -q 参数不能同时使用!')
            sys.exit(-1)

        # 配置 loguru 日志级别
        logger.remove()  # 移除默认处理器
        if args.verbose:
            logger.add(sys.stderr, level='DEBUG')
        elif args.quite:
            logger.add(sys.stderr, level='ERROR')
        else:
            logger.add(sys.stderr, level='INFO')

        compiler = T2kSCompiler(args.allow_non_user_area)

        logger.info('开始编译...')
        # 执行编译流程
        compiler.compile_file(args.input_file, args.output_file, args.start_location)
        logger.info('编译结束！')
    except (FileNotFoundError, IsADirectoryError, T2kSSyntaxError, T2kSJumpError, T2kSLabelRepeatError) as e:
        logger.error(e)
        sys.exit(-1)
    except Exception as e:
        logger.error(f'预期外错误: {e}')
        sys.exit(-1)


if __name__ == '__main__':
    main()
