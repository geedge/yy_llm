from openai import OpenAI

def convert_json_to_text(data):
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
    text.append("（9）开启了IPv6功能")  # 假设IPv6始终开启

    # 返回拼接好的文本
    return "；".join(text)


client = OpenAI(
    api_key="sk-wFEcyFj8sS2mbncCEqYK5uxYa6VyQyJrQ8reKPFYzxQcwt3i",
    base_url="https://api.moonshot.cn/v1",
)

# 加载背景介绍信息
with open('./content_role_system.txt', 'r', encoding='utf-8') as f:
    content_system = f.read()

output_constraints = "请按下面规定的格式输出策略调整结果，从下面的集合中选择一种决策输出（不需要其他任何文字反馈，我需要处理格式化输出的内容）：{保持当前策略执行、调整脚本参数：参数代称 原始的数值->新的数值、更换攻击脚本：脚本名称}"

mode_mapping = {"保持当前策略执行": "keep",
                "调整脚本参数": "parameter",
                "更换攻击脚本": "script"}

history = [
    {"role": "system",
     "content": content_system}
]


def chat(query, history):
    history.append({
        "role": "user",
        "content": query
    })
    completion = client.chat.completions.create(
        model="moonshot-v1-32k",
        messages=history,
        temperature=0.3,
    )
    result = completion.choices[0].message.content
    history.append({
        "role": "assistant",
        "content": result
    })
    return result


def initial(content):
    global history
    history = [
        {"role": "system",
         "content": content_system}
    ]

    clxz_map = {
        "ddos": "拒绝服务",
        "sjqp": "数据欺骗"
    }

    try:
        clxz = clxz_map.get(content["clxz"], None)      # 策略选择
        # _mbgz =      # 目标感知
        mbgz = convert_json_to_text(content["mbgz"])
        ztgz = content["ztgz"]      # 状态感知
        _script = content["script"]  # 脚本
        _param = content["para"]    # 传来的脚本参数是字典形式的
        param = ""  # 将参数转换成字符串
        for p, v in _param.items():
            if param == "":
                param += f"{p}-{v}"
            else:
                param += f"-{p}-{v}"
        script = f"{_script.replace(' ', '_')};{_script.replace(' ', '_').lower()}_{param}"
    except Exception as e:
        raise Exception('post上传的数据key解析失败', e)

    # 构建待上传ai的策略初始化信息
    assert clxz in ["拒绝服务", "数据欺骗"], "策略选择只能是'拒绝服务'或者'数据欺骗'"
    clxz_context = f"1. 测试的最终目的是：{clxz}"

    mbgz_context = f"2. 当前目标节点的18维不变特性是：{mbgz}"

    script = script.replace('；', ';').split(';')
    script_context = f"3. 当前执行的脚本名称为{script[0]}；" + ("脚本参数选择为" + "；".join(script[1:]) if len(script) > 1 else "")

    ztgz_context = f"4. 当前（未执行脚本前）目标节点的状态参数为：DNS服务应答率{ztgz['record']*100}%；icmp时延{ztgz['icmp']}ms；udp时延{ztgz['dns']}ms；tcp时延{ztgz['tcp']}ms；pps为200kpps"

    context = '\n'.join([clxz_context, mbgz_context, script_context, ztgz_context])

    # 初始化交互不需要输出响应
    chat(context, history)
    return 1


def adjust_to_dict(adjust: str):
    """
        将大模型返回的script字符串转换成字典，如 doh_ddos-n-100-200-abc-1000-f, 将被转换为
        {
            "script": "doh_ddos", (此处doh_ddos也可能被映射成其它的，具体跟mp中的映射关系有关)
            "parameter": {
                "n": ["100", "200"],
                "abc": ["1000"],
                "f": []
            }
        }
    """
    print(adjust)
    if adjust == "none":
        return {
            "script": "none",
            "parameter": {
            },
        }
    # 这个字典负责将大模型返回的策略名称映射到规定的名称
    mp = {
        "v6_数据篡改": "V6 数据篡改",
        "<v6_数据篡改>": "V6 数据篡改",
        "v6_poisoning": "V6 数据篡改",
        "<v6_poisoning>": "V6 数据篡改",
        "dnssec_ddos": "DNSSEC ddos",
        "<dnssec_ddos>": "DNSSEC ddos",
        "DNSSEC_DDoS": "DNSSEC ddos",
        "<DNSSEC_DDoS>": "DNSSEC ddos",
        "dnssec_降级": "DNSSEC 降级",
        "<dnssec_降级>": "DNSSEC 降级",
        "DNSSEC_downgrade": "DNSSEC 降级",
        "<DNSSEC_downgrade>": "DNSSEC 降级",
        "dnssec_downgrade": "DNSSEC 降级",
        "<dnssec_downgrade>": "DNSSEC 降级",
        "DNS_IPv6_DDoS": "V6 DDoS",
        "<DNS_IPv6_DDoS>": "V6 DDoS",
        "ipv6_ddos": "V6 DDoS",
        "<ipv6_ddos>": "V6 DDoS",
        "v6_ddos": "V6 DDoS",
        "<v6_ddos>": "V6 DDoS",
        "DNS_IPv6_inject": "V6 数据篡改",
        "<DNS_IPv6_inject>": "V6 数据篡改",
        "v6_数据篡改": "V6 数据篡改",
        "<v6_数据篡改>": "V6 数据篡改",
        "dns_ipv6_inject": "V6 数据篡改",
        "<dns_ipv6_inject>": "V6 数据篡改",
        "DNS_IPv6_poisoning": "V6 数据篡改",
        "<DNS_IPv6_poisoning>": "V6 数据篡改",
        "dot_ddos": "DoT DDoS",
        "<dot_ddos>": "DoT DDoS",
        "DoT_DDoS": "DoT DDoS",
        "<DoT_DDoS>": "DoT DDoS",
        "dot_poisoning": "DoT 数据篡改",
        "<dot_poisoning>": "DoT 数据篡改",
        "DoT_poisoning": "DoT 数据篡改",
        "<DoT_poisoning>": "DoT 数据篡改",
        "dot_数据篡改": "DoT 数据篡改",
        "<dot_数据篡改>": "DoT 数据篡改",
        "dot_数据注入": "DoT 数据注入",
        "<dot_数据注入>": "DoT 数据注入",
        "dot_inject": "DoT 数据注入",
        "<dot_inject>": "DoT 数据注入",
        "DoT_inject": "DoT 数据注入",
        "<DoT_inject>": "DoT 数据注入",
        "DoH_DDoS": "DoH DDoS",
        "<DoH_DDoS>": "DoH DDoS",
        "doh_ddos": "DoH DDoS",
        "<doh_ddos>": "DoH DDoS",
        "doh_数据注入": "DoH 数据注入",
        "<doh_数据注入>": "DoH 数据注入",
        "doh_inject": "DoH 数据注入",
        "<doh_inject>": "DoH 数据注入",
        "DoH_inject": "DoH 数据注入",
        "<DoH_inject>": "DoH 数据注入",
        "doh_数据篡改": "DoH 数据篡改",
        "<doh_数据篡改>": "DoH 数据篡改",
        "doh_poisoning": "DoH 数据篡改",
        "<doh_poisoning>": "DoH 数据篡改",
        "DoH_poisoning": "DoH 数据篡改",
        "<DoH_poisoning>": "DoH 数据篡改"
    }
    adjust = adjust.replace("<", "")
    adjust = adjust.replace(">", "")
    index = 0
    for i in range(len(adjust)):
        if adjust[i] == '_':
            index = i
        if adjust[i] == '-':
            index = i
            break
    if '-' not in adjust:
        script = adjust
        param_list = []
    else:    
        script = adjust[:index]
        param_list = adjust[index+1:].split('-')
    
    res_dict = {}
    left, right = 0, 0
    def is_parma_value(s):
        """
            这个函数只会在下面的while中使用，作用是判断一个字符串，是数值串还是字符串
        """
        try:
            int(s)
        except:
            return False
        return True
    while len(param_list):
        right += 1
        while right < len(param_list) and is_parma_value(param_list[right]):
            right += 1
        curr_param = param_list[left]
        res_dict[curr_param] = []
        left += 1
        while left < right:
            res_dict[curr_param].append(int(param_list[left]))
            left += 1
        # 将数组处理成一个数值，如果脚本参数存在一参对多值的情况如 -n 1 2 3 4, 则删除此部分
        if len(res_dict[curr_param]):
            res_dict[curr_param] = sum(res_dict[curr_param])//len(res_dict[curr_param])
        else:
            res_dict[curr_param] = None
        if left >= len(param_list):
            break
    
    try:
        return {
            "script": mp[script],
            "parameter": res_dict
        }
    except:
        return {
            "script": script,
            "parameter": res_dict
        }
        # raise f"在将大模型返回的脚本字符串转换成字典时出现错误，原因是 mp 中并没有键: {script}"


def adjusting(content):
    try:
        ztgz = content["ztgz"]      # 状态感知
    except Exception as e:
        raise Exception("post上传的数据key解析失败", e)

    context = f"当前目标节点的状态感知结果为：DNS服务应答率{ztgz['record']*100}%；icmp时延{ztgz['icmp']}ms；udp时延{ztgz['dns']}ms；tcp时延{ztgz['tcp']}ms；pps为200kpps\n{output_constraints}"

    response = chat(context, history)

    mode = response.replace(":", "：").split("：")[0]
    assert mode in ["保持当前策略执行", "调整脚本参数", "更换攻击脚本"], f"响应出现非标情况，当前模式响应为{mode}"
    mode_context = mode_mapping[mode]

    try:
        if mode_context == "keep":
            adjust_context = "none"
        elif mode_context == "parameter":
            # 例如：模型响应：调整脚本参数：doh_ddos_n 4->8  输出adjust参数为doh_ddos_n-8
            para = response.replace(":", "：").split("：")[1]
            adjust_context = "-".join([para.split(" ")[0], para.split(">")[-1]])
        else:
            # 例如：模型响应：更换攻击脚本：DoT_DDoS   输出adjust参数为DoT_DDoS
            adjust_context = response.replace(":", "：").split("：")[1]
    except Exception as e:
        raise Exception("处理模型规范化输出错误", e)

    # # debug
    # print(history)
    res = adjust_to_dict(adjust_context)
    res.update({"mode": mode_context})

    return res


if __name__ == "__main__":
    print(adjust_to_dict('dddd'))
