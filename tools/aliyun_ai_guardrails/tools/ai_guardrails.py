from collections.abc import Generator
from typing import Any
import base64
import hmac
import hashlib
from urllib.parse import quote
import requests
from datetime import datetime
from datetime import timezone
import uuid
import json
import re
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
import concurrent.futures
from functools import partial

ENCODING = "UTF-8"
ISO8601_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
ALGORITHM = "HmacSHA1"
MAX_LENGTH = 2000


def format_iso8601_date():
    return datetime.now(timezone.utc).strftime(ISO8601_DATE_FORMAT)


def percent_encode(value):
    if value is None:
        return ""
    return (
        quote(value.encode(ENCODING), safe="~").replace("+", "%20").replace("*", "%2A")
    )


def create_signature(string_to_sign, secret):
    secret = secret + "&"
    signature = hmac.new(
        secret.encode(ENCODING), string_to_sign.encode(ENCODING), hashlib.sha1
    ).digest()
    return base64.b64encode(signature).decode(ENCODING)


def create_string_to_sign(http_method, parameters):
    sorted_keys = sorted(parameters.keys())
    canonicalized_query_string = ""

    for key in sorted_keys:
        canonicalized_query_string += (
            "&" + percent_encode(key) + "=" + percent_encode(parameters[key])
        )

    string_to_sign = (
        http_method
        + "&"
        + percent_encode("/")
        + "&"
        + percent_encode(canonicalized_query_string[1:])
    )
    return string_to_sign

def split_text(text: str, max_length: int = 1950) -> list[str]:
    """将文本按 max_length 分段，尽量保留完整句子（识别多种标点）"""
    segments = []
    while len(text) > max_length:
        # 提取当前最大长度范围内的子串
        chunk = text[:max_length]

        # 使用正则查找最后一个句号、感叹号、问号等断句符号的位置
        match = None
        for pattern in [r'[。！？；:\.?!]+']:  # 匹配多种结束符号
            matches = list(re.finditer(pattern, chunk))
            if matches:
                match = matches[-1]  # 取最后一个匹配项

        if match:
            cut_point = match.end()  # 包含标点符号
        else:
            cut_point = max_length  # 找不到就强制截断

        segments.append(text[:cut_point])
        text = text[cut_point:]

    if text:
        segments.append(text)
    return segments

class AiGuardrailsTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        # 1. 从运行时获取凭证
        try:
            aliyun_access_key = self.runtime.credentials["aliyun_access_key"]
        except KeyError:
            raise Exception("阿里云 Access Key 未配置或无效。请在插件设置中提供。")
        try:
            aliyun_access_secret = self.runtime.credentials["aliyun_access_secret"]
        except KeyError:
            raise Exception("阿里云 Access Secret 未配置或无效。请在插件设置中提供。")

        # 从凭证中读取 region，默认使用 cn-shanghai
        region = self.runtime.credentials.get("region", "cn-shanghai")
        service_url = f"https://green-cip.{region}.aliyuncs.com"

        # 2. 获取工具输入参数
        content = tool_parameters.get("content", "")  # 使用 .get 提供默认值
        type = tool_parameters.get("type", "")
        modalType = tool_parameters.get("modalType", "")
        imageUrl = tool_parameters.get("imageUrl", "")
        fileUrl = tool_parameters.get("fileUrl", "")
        customService = tool_parameters.get("customService", "")
        service = ""
        params = {}

        if customService or modalType == "custom" or type == "custom":
            # 用户选择了自定义服务，直接使用
            if not customService:
                raise Exception("选择了'自定义'时，必须填写自定义服务名称。")
            if modalType != "custom" or type != "custom":
                raise Exception("填写了自定义服务时，模态类型和检测类型均需选择'自定义'。")
            service = customService
            if content and imageUrl:
                params = {"content": content, "imageUrls": [imageUrl]}
            elif content and fileUrl:
                params = {"content": content, "fileUrls": [fileUrl]}
            elif content:
                params = {"content": content}
            elif imageUrl:
                params = {"imageUrls": [imageUrl]}
            elif fileUrl:
                params = {"fileUrls": [fileUrl]}
        else:
            # 未填写自定义服务，使用原有 modalType + type 路由逻辑
            if not modalType:
                raise Exception("模态不能为空。")
            if modalType=="text" and not content:
                raise Exception("检测文本内容不能为空。")
            if modalType=="image" and not imageUrl:
                raise Exception("检测图片地址不能为空。")
            if modalType=="file" and not fileUrl:
                raise Exception("检测文件地址不能为空。")
            if modalType=="modal_text_file" and (not fileUrl or not content):
                raise Exception("检测文件地址和文本内容不能为空。")
            if modalType=="modal_text_image" and (not imageUrl or not content):
                raise Exception("检测图片地址和文本内容不能为空。")
            if not type:
                raise Exception("检测类型不能为空。")

            # 文本模态才支持长文
            if modalType!="text" and len(content) > MAX_LENGTH :
                raise Exception(f"文本内容不能超过{MAX_LENGTH}字符。")

            if modalType=="text" and type == "input" :
                service = "query_security_check"
                params = {"content": content}
            elif modalType=="text" and type == "output" :
                service = "response_security_check"
                params = {"content": content}
            elif modalType=="image" and type == "input" :
                service = "img_query_security_check"
                params = {"imageUrls":[imageUrl]}
            elif modalType=="image" and type == "output" :
                service = "img_response_security_check"
                params = {"imageUrls":[imageUrl]}
            elif modalType=="file" :
                service = "file_security_sync_check"
                params = {"fileUrls":[fileUrl]}
            elif modalType=="modal_text_file" :
                service = "text_file_sec_sync_check"
                params = {"content": content, "fileUrls":[fileUrl]}
            elif modalType=="modal_text_image" :
                service = "text_img_security_check"
                params = {"content": content, "imageUrls":[imageUrl]}

        #将长文本拆分成2000一段（纯文本场景：params 只有 content，没有图片/文件）
        is_text_only = "content" in params and "imageUrls" not in params and "fileUrls" not in params
        if is_text_only and content and len(content) > MAX_LENGTH:
            contents = split_text(content, MAX_LENGTH-50)
        elif is_text_only and content:
            contents = [content]
        else:
            contents = None

        # 3. 调用库执行操作
        def request(service, params):

            # 给params添加来源参数
            params["requestFrom"] = "DifyPlugin"
            
            # 3.1 构造请求参数
            parameters = {
                "Action": "MultiModalGuard",
                "Version": "2022-03-02",
                "AccessKeyId": aliyun_access_key,
                "Timestamp": format_iso8601_date(),
                "SignatureMethod": "HMAC-SHA1",
                "SignatureVersion": "1.0",
                "SignatureNonce": str(uuid.uuid4()),
                "Format": "JSON",
                "Service": service,
                "ServiceParameters": json.dumps(params, ensure_ascii=False),
            }

            string_to_sign = create_string_to_sign("POST", parameters)
            signature = create_signature(string_to_sign, aliyun_access_secret)
            parameters["Signature"] = signature
            
            # 3.2 发送请求
            response = requests.post(service_url, data=parameters)
            body = response.json()

            if response.status_code != 200:
                raise Exception(
                    f"response http status_code not 200. status_code: {response.status_code}, body: {body}"
                )

            if body.get("Code") != 200:
                raise Exception(
                    f"response code not 200. code: {body.get('Code')}, body: {body}"
                )
            
            return body
        
        try:
            
            # 纯文本且需要切分时并发执行
            bodys = []
            if contents:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(request, service, {"content": seg}) for seg in contents]
                    for future in concurrent.futures.as_completed(futures):
                        bodys.append(future.result())
            else:
                bodys.append(request(service, params))
                    
            # 4. 返回结果

            # 文本输出
            # yield self.create_text_message(f"Processed result: {body}")

            # JSON输出
            yield self.create_json_message({"results":bodys})

            contentModerationSuggestion=""
            sensitiveDataSuggestion=""
            promptAttackSuggestion=""
            maliciousUrlSuggestion=""
            maliciousFileSuggestion=""
            customLabelSuggestion=""
            waterMark=""
            desensitization=""
            _finalSuggestion="pass"

            # 遍历bodys
            for body in bodys:
                finalSuggestion = body.get("Data", {}).get("Suggestion", "")
                detailList = body.get("Data", {}).get("Detail", [])
                if finalSuggestion and _finalSuggestion!="block" :
                    _finalSuggestion = finalSuggestion
                for detail in detailList:
                    suggestion = detail.get("Suggestion", "")
                    type = detail.get("Type", "")
                    if type == "contentModeration":
                        if suggestion and contentModerationSuggestion!="block" :
                            contentModerationSuggestion = suggestion
                    elif type == "sensitiveData":
                        desensitization = detail.get("Result",[])[0].get("Ext",{}).get("Desensitization","")
                        if suggestion and sensitiveDataSuggestion!="block" :
                            sensitiveDataSuggestion = suggestion
                    elif type == "promptAttack":
                        if suggestion and promptAttackSuggestion!="block" :
                            promptAttackSuggestion = suggestion
                    elif type == "maliciousUrl":
                        if suggestion and maliciousUrlSuggestion!="block" :
                            maliciousUrlSuggestion = suggestion
                    elif type == "maliciousFile":
                        if suggestion and maliciousFileSuggestion!="block" :
                            maliciousFileSuggestion = suggestion
                    elif type == "waterMark":
                        waterMark = detail.get("Result",[])[0].get("Ext",{}).get("FileUrl","")
                    elif type == "customLabel":
                        if suggestion and customLabelSuggestion!="block" :
                            customLabelSuggestion = suggestion

            # 变量输出 (用于工作流)
            yield self.create_variable_message("contentModerationSuggestion", contentModerationSuggestion)
            yield self.create_variable_message("sensitiveDataSuggestion", sensitiveDataSuggestion)
            yield self.create_variable_message("promptAttackSuggestion", promptAttackSuggestion)
            yield self.create_variable_message("maliciousUrlSuggestion", maliciousUrlSuggestion)
            yield self.create_variable_message("maliciousFileSuggestion", maliciousFileSuggestion)
            yield self.create_variable_message("customLabelSuggestion", customLabelSuggestion)
            yield self.create_variable_message("waterMark", waterMark)
            yield self.create_variable_message("desensitization", desensitization)
            yield self.create_variable_message("_finalSuggestion", _finalSuggestion) 
            
        except Exception as e:
            # 如果库调用失败，抛出异常
            raise Exception(f"调用 Ai Guardrails API 失败: {e}")
