import json
from datetime import datetime
from openai import OpenAI
from loguru import logger


# logger初始化
# 获取当前日期，并用作日志文件名的一部分
log_filename = f"{datetime.now().strftime('%Y-%m-%d')}_run.log"

# 添加日志记录，设置日志文件的旋转时间、日志格式以及日志级别
logger.add(log_filename, rotation="1 week", format="{time:YYYY-MM-DD HH:mm:ss} - {level} - {message}", level="INFO")

client = OpenAI(
    api_key="sk-wFEcyFj8sS2mbncCEqYK5uxYa6VyQyJrQ8reKPFYzxQcwt3i",
    base_url="https://api.moonshot.cn/v1",
)
sessions_with_boss : dict[str,list]={}     # 每个session负责记录每个task与gpt交互的历史记录 {session_id/task_id: history}

# 加载背景介绍信息(提示词)
try:
    with open('./strategy_adjust_code/content_role_system.txt', 'r', encoding='utf-8') as f:
        system_prompt = f.read()
except:
    logger.error("系统提示词加载失败，请检查提示词文件路径")
    exit(0)

def chat(query: str, session_id: list):
    global sessions_with_boss
    # 检验 session 是否存在
    if session_id not in sessions_with_boss.keys():
        # 在别已经有log记录了
        return None
    
    # 获得历史记录，处理最多保留10次会话内容
    history = keep_len_history(history=sessions_with_boss[session_id][0], length=10)
    history.append({
        "role": "user",
        "content": query
    })
    # 将提示词（历史记录）发送给GPT，询问结果
    completion = client.chat.completions.create(
        model="moonshot-v1-32k",
        messages=history,
        response_format={'type': 'json_object'},  # 使用此值需要在提示词中给出json格式
        # temperature=0.3,    # 回答的随机程度0-2，越低越确定（不随机）
    )
    # GPT的响应结果，可能有多个，默认使用第一个 choices[0]
    result = completion.choices[0].message.content
    # 更新到每个session的历史记录中, 并更新会话存活时间
    sessions_with_boss[session_id][0].append({
        "role": "user",
        "content": query
    })
    sessions_with_boss[session_id][0].append({
        "role": "assistant",
        "content": result
    })
    sessions_with_boss[session_id][1] = datetime.now()

    return result


def keep_len_history(history: list[dict], length: int=10):
    """
        保留length长度的历史记录
        param length: 需要保留的历史记录的长度，一问一答为一个长度，为0则保留所有
    """
    res_history = list()
    # 保留系统提示词
    for item in history:
        if item['role'] == 'system':
            # ?注意，这里是否会出现深浅拷贝的问题呢，查一下?
            res_history.append(item)
    # 切片，保留后length的聊天记录
    res_history.extend(history[-2*min(length, len(history)):])
    return res_history


def mbgz_to_desc(data):
    """
        将目标节点的特点，转换成文本描述，initial()会使用此函数，其它地方未使用
    """
    text = []

    # 判断 DNSSEC 启用情况
    if data.get("dnssec_enabled", False):
        text.append("（2）开启DNSSEC")
    else:
        text.append("（2）未开启DNSSEC")

    # 是否使用 0x20 编码（域名随机化大小写）
    if data.get("0x20_encoding", False):
        text.append("（3）不可以使用缓存投毒")
    else:
        text.append("（3）可以使用缓存投毒")

    # 判断是否支持DDoS
    if data.get("merge_dup", False):
        text.append("（4）不适用DDoS")
    else:
        text.append("（4）可使用DDoS")

    # 判断是否适用 DNSSEC_DDoS
    if data.get("dnssec_enabled", False) and not data.get("random_port", False):
        text.append("（5）不适用DNSSEC_DDoS")
    else:
        text.append("（5）适用DNSSEC_DDoS")

    # 判断是否适用放大攻击
    if data.get("max_ns_cnt", 0) > 4:
        text.append("（6）适用放大攻击")
    else:
        text.append("（6）不适用放大攻击")

    # 是否开启 DoH 和 DoT
    if data.get("edns_support", False):
        text.append("（7）开启了DoH")
    else:
        text.append("（7）未开启DoH")

    text.append("（8）开启了DoT")  # 假设DoT始终开启

    # IPv6 启用情况
    text.append("（9）未开启了IPv6功能")  # 假设IPv6始终开启

    # 返回拼接好的文本
    return "；".join(text)


def parse_query_content(content: dict):
    """
        解析主控端（boss）发送来的content，转换成GPT需要的描述格式
    """
    if content['clxz'] == 'ddos':
        clxz_desc = "拒绝服务攻击，使用ddos脚本，使得目标DNS服务器不能响应正常DNS请求"
    elif content['clxz'] == 'sjqp':
        clxz_desc = "数据欺骗攻击，使用inject或poisoning脚本，使得目标DNS服务器响应错误的数据"
    elif content['clxz'] == 'auto':
        clxz_desc = "根据渗透节点的特点，选择 拒绝服务攻击 或 数据欺骗攻击"
    else:
        logger.error(f"parameter error: clxz is not ddos or sjqp, but {content['clxz']}")
        return {'error': f'clxz策略选择只能为ddos/sjqp/auto，收到了{content["clxz"]}'}
    mbgz_desc = mbgz_to_desc(content['mbgz'])
    try:
        ztgz_desc = {
            "response_rate": f"{float(content['ztgz']['record']) * 100}%",
            "icmp_rr": f"{content['ztgz']['icmp']}ms",
            "udp_rr": f"{content['ztgz']['dns']}ms",
            "tcp_rr": f"{content['ztgz']['tcp']}ms",
            "pps": '200kbps'
        }
    except Exception as e:
        return {'error': 'ztgz中存在参数错误, {e}'}
    
    script = content['script']
    legal_script_name = ['DNSSEC DDoS', 'DNSSEC downgrade', 'DNS IPv6 DDoS', 'DNS IPv6 inject', 'DNS IPv6 poisoning',
                      'DoT DDoS', 'DoH DDoS', 'DoH poisoning', 'DoT poisoning', 'DoH inject', 'DoT inject']
    if script not in legal_script_name:
        logger.error(f'script value error: {script}, we need it is one of {legal_script_name}')
        return {'error': f'script value error: {script}, we need it is one of {legal_script_name}'}
    params = content['para']
    # TODO 检查 params
    if params:
        pass
    # TODO session_id/task_id的检查
    session_id = content['task_id']

    return {
        'clxz': clxz_desc,
        'mbgz': mbgz_desc,
        'ztgz': ztgz_desc,
        'script': script,
        'params': params,
        'session_id': session_id
    }


def parse_gpt_response(gpt_res_txt: dict, query: dict):
    """
        gpt_res_txt格式为:{
                            "next_step": "adjust_param"/"adjust_script"/"keep",
                            "next_script": <推荐执行的脚本名称>
                            "params": {
                                "<参数名>": "<推荐的参数值>",
                                ...
                            },
                            "reason": <做出此判断的依据>
                        }
        此函数将gpt的返回格式处理成主控端需要的格式
    """
    mp = {
            "DNSSEC DDoS": "DNSSEC ddos",
            "DNSSEC downgrade": "DNSSEC 降级",
            "DNS IPv6 DDoS": "V6 DDoS",
            "DNS IPv6 inject": "V6 数据注入",
            "DNS IPv6 poisoning": "V6 数据篡改",
            "DoT DDoS": "DoT DDoS",
            "DoT poisoning": "DoT 数据篡改",
            "DoT inject": "DoT 数据注入",
            "DoH DDoS": "DoH DDoS",
            "DoH inject": "DoH 数据注入",
            "DoH poisoning": "DoH 数据篡改",
        }
    gpt_res = json.loads(gpt_res_txt)
    next_step = gpt_res.get("next_step", None)
    if not next_step or next_step not in ["keep", "adjust_params", "adjust_script"]:
        return {'error': 'GPT 返回格式错误'}
    if next_step == "keep":
        next_script = query.get("script")
        new_params = query.get("params")
    elif next_step == "adjust_params":
        next_script = query.get("script")
        new_params = gpt_res.get("params", None)
    elif next_step == "adjust_script":
        next_script = gpt_res.get("next_script", None)
        new_params = gpt_res.get("params", None)
    else:
        next_script, new_params = None, None
    # 如果没有给出下一步脚本
    if not next_script:
        return {'error': 'GPT 推荐调整脚本，但未给出具体的脚本名称'}
    # 如果给出了下一步脚本，但是脚本需要的参数未给出
    if next_script in ['DNSSEC DDoS', 'DNS IPv6 DDoS', 'DoT DDoS', 'DoH DDoS'] and not new_params:
        return {'error': 'GPT 推荐调整参数，但未给出具体的值'}
    
    next_script_desc = mp.get(next_script, None)
    return {
        'mode': next_step,
        'script': next_script_desc if next_script_desc else next_script,
        'parameter': new_params,
        'reason': gpt_res.get('reason', 'GPT未给出原因'),
        'error': None
    }

################# 下面是接口部分 #################

"""
    接口的标准输入：
        type: dict/json
        format: {
            "clxz": "ddos"/"sjqp",
            "mbgz": {
                ... 太多了省略，和以前一样
            },
            "ztgz": {
                "icmp": <vaule>,
                "dns": <value>,
                "tcp": <value>,
                ... 其它无所谓
            },
            "script": <脚本名称>,
            "para": {
                ... 脚本参数，为空时推荐填入空字典
            },
            "task_id": <任务id ，确保唯一即可>
        }

    接口标准返回：
        type: dict/json
        format: {
            "mode": "adjust_params"/"adjust_script"/"keep",
            "script": <推荐执行的脚本名称>
            "parameter": {
                "<参数名>": "<推荐的参数值>",
                ...
            },
            "reason": <做出此判断的依据>,
            "error": None
        }
    接口出错返回: 
        type: dict/json
        format: {
            "mode": "keep",
            "script": <原脚本>
            "parameter": {
                "<参数名>": "<原参数值>",
                ...
            },
            "reason": <出错原因>
            "error": <出错简述，现在只有"parameter error"/"gpt error">
        }
""" 
@logger.catch   # 只有没被处理的异常才会被记录
def initial(content: dict):
    """
        为一个新的需要大模型辅助的task创建session。session主要记录task和此task与大模型对话的历史记录
    """
    global sessions_with_boss
    # 1. 解析传来的请求
    content_body = parse_query_content(content=content)
    if 'error' in content_body.keys():
        return content_body['error']
    # 2. 确定最终攻击目标

    # 3. 创建session id
    new_session_id = content_body['session_id']
    
    # 4. 创建新的session会话
    new_history = [
        {
            "role": "system",
            "content": system_prompt % (content_body['clxz'], content_body['mbgz'])
        },
    ]
    active_time = datetime.now()  # 类似cookie的有效时间，超时此会话可能会被删除
    sessions_with_boss.update({new_session_id: [new_history, active_time]})
    logger.info(f"为task: {new_session_id}创建了新的session")
    
    try:
        # 4. 与GPT对话（第一次提问）（似乎不需要）
        # query = {
        #     "script": content_body['script'],
        #     "params": content_body['params'],
        #     "target_status": content_body['ztgz'],
        #     "last_exe_desc": "无"
        # }
        # chat(query=json.dumps(query), session_id=new_session_id)
        return 1
    except Exception as e:
        return -1

@logger.catch   # 只有没被处理的异常才会被记录
def adjusting(content: dict):
    """
        调整策略
    """
    global sessions_with_boss
    # 1. 解析传来的请求
    content_body = parse_query_content(content=content)
    if 'error' in content_body.keys():
        return {
                "mode": "keep",
                "script": None,
                "parameter": None,
                'error': 'parameter error',
                "reason": content['error']
            }
    curr_session_id = content_body['session_id']
    # 2. 与GPT对话
    query = {
        "script": content_body['script'],
        "params": content_body['params'],
        "target_status": content_body['ztgz'],
        "last_exe_desc": "无"
    }
    try:
        gpt_response = chat(query=json.dumps(query), session_id=curr_session_id)
        if gpt_response:
            # 3. 处理GPT返回的结果
            res = parse_gpt_response(gpt_res_txt=gpt_response, query=query)
            if 'error' in res.keys() and res['error']:
                logger.error(f"请求gpt时出现错误: {res['error']}")
                return {
                    "mode": "keep",
                    "script": query.get('script'),
                    "parameter": query.get('params', {}),
                    'error': 'gpt error',
                    "reason": res['error']
                }
            else:
                logger.info(f"当前节点状态为：\n" + 
                            f"{content_body['ztgz']} \n" + 
                            f"策略调整，script: {query['script']}, params: {query['params']} --> script: {res['script']}, params: {res['parameter']}. reason: {res['reason']}")
            return res
        else:
            logger.error(f"session id: {curr_session_id} not exist, please call initial-api first.")
            return {
                "mode": "keep",
                "script": query.get('script'),
                "parameter": query.get('params', {}),
                'error': 'parameter error',
                "reason": "调用initial接口传入了一个无效的session_id/task_id, 你应该先调用initial接口"
            }
    except Exception as e:
        logger.error(f"请求gpt时出现错误: {e}")
        return {
                "mode": "keep",
                "script": query.get('script', ''),
                "parameter": query.get('params', {}),
                'error': 'gpt error',
                "reason": "调用gpt时出现错误，可能时Token消耗完了"
            }
