# 执行流程
# 1. 接收初始化指令，获得参数包括策略选择<拒绝服务；数据欺骗>；目标感知结果；状态感知结果；初始的攻击脚本及参数 --> 初始化接口调用
#   1.1 创建会话
#   1.2 发送第一条信息，介绍任务背景信息（与下面的合并）
#   1.3 发送第一条信息，格式化上述参数，并发送当前任务介绍
# 2. 接收询问策略调整命令，获得参数包括状态感知结果 --> 询问策略调整接口

from flask import Flask, request, jsonify
import kimi_main2

app = Flask(__name__)


@app.route('/initial', methods=['POST'])
def process_initial():
    data = request.get_json()
    if kimi_main2.initial(data):
        return jsonify({"message": "Task processed"}), 200
    else:
        return jsonify({"error": "Service is currently unavailable"}), 503


@app.route('/adjustment', methods=['POST'])
def process_adjustment():
    data = request.get_json()
    kimi_response = kimi_main2.adjusting(data)
    return jsonify(kimi_response), 200


if __name__ == '__main__':
    app.run(port=5006)