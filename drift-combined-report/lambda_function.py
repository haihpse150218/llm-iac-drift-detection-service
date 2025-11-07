# lambda_function.py
import os
import json
import random
import boto3
import logging
import time
import re
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3 = boto3.client("s3")

# CONFIG
REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "LBQSCKGFJM")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "NTCPG9HUZF")

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("repoSubscriptions")
sf = boto3.client("stepfunctions")
STEP_FUNCTION_ARN = os.environ.get("STEP_FUNCTION_ARN", "arn:aws:states:us-east-1:933000400558:stateMachine:DriftReportAgentASL")
lambda_client = boto3.client("lambda")
LAMBDA_NAME = os.environ.get("LAMBDA_NAME", "iacScanOrchestrator")

bedrock = boto3.client("bedrock-agent-runtime", region_name=REGION)

# PROMPT – ĐÃ LOẠI BỎ CÁC PLACEHOLDER KHÔNG CẦN
PROMPT = """
You are an expert in Infrastructure as Code (IaC) drift analysis and remediation. 
Your task is to combine two separate drift analysis reports, one focusing on 'Iacdriftandupdateremediation' remediation and the other on 'Iacdriftandremovesourceremediation' remediation, into a single, comprehensive report. The combined report must clearly present all identified drift issues from both original reports, along with both sets of remediation suggestions, allowing the user to understand and choose between the presented options.
# Step by Step instructions
1. Read the Iac Drift And Update Remediation report.
2. Read the Iac Drift And Remove Source Remediation report.
3. Identify and extract all drift issues from both reports.
4. Identify and extract all 'update IaC' remediation suggestions from the Iac Drift And Update Remediation report.
5. Identify and extract all 'remove source' remediation suggestions from the Iac Drift And Remove Source Remediation report.
6. Combine the extracted drift issues into a single, comprehensive list, ensuring no duplicates.
7. Combine the extracted 'update IaC' and 'remove source' remediation suggestions into a single, comprehensive list, clearly associating each suggestion with its respective drift issue and remediation type.
8. Structure the combined report to clearly present all identified drift issues, followed by both sets of remediation suggestions (update IaC and remove source) for each issue. Ensure the user can easily understand and choose between the presented options.

Iacdriftandremovesourceremediation
```
{remove_remediation}
```

Iacdriftandupdateremediation
```
{update_remediation}
```
IMPORTANT NOTE: Start directly with the output, do not output any delimiters. 
Show details content of configure where have problem to user easily view point and link to **terraform source** which is fields content of Iac Configuration and AWS Desired State
Iac Configuration Description:
```
Find **ALL** IaC resources have detection above from the Knowledge Base.  
**All IaC configurations are stored under the directory `iac_config/` in the KB.**
```
Desired State Description:
```
Find **ALL** corresponding AWS State resources have detection above (where `status != deleted`).  
**All AWS Desired State configurations are stored under the directory `aws_state/` in the KB.**
```

Output JSON:
{{
  "report_id": "drift-{date}",
  "total_drift": 5,
  "high_risk": 2,
  "drifted_resources": [
    "[type detection]":[
        [remediation_type]":[
            remediation_suggestions: {{
            "resource_address": "aws_instance.example",
            "issue": "instance_type mismatch",
            "details": "Config: t3.micro → t3.small | Source: main.tf#L12 | Desired: t3.micro",
            "remediation_update_iac": "Update instance_type = \\"t3.micro\\"",
            "remediation_remove_source": "N/A"
            }}
        ]
    ]
  ],
  "summary": "5 drifts found, 2 high-risk",
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- The output must always be valid JSON following the specified schema.
"""

PROMPTT_GENERATE_HTML = """
You are an AI Web Developer. Your task is to generate a single, self-contained HTML document for rendering in an landing page, based on user instructions and Data Drift Analysis Report.

**Visual aesthetic:**
    * Aesthetics are crucial. Make the page look amazing, especially on mobile.
    * Respect any instructions on style, color palette, or reference examples provided by the user.

**Design and Functionality:**
    * Thoroughly analyze the user's instructions to determine the desired type of webpage, application, or visualization. What are the key features, layouts, or functionality?
    * Analyze any provided data to identify the most compelling layout or visualization of it. For example, if the user requests a visualization, select an appropriate chart type (bar, line, pie, scatter, etc.) to create the most insightful and visually compelling representation. Or if user instructions say `use a carousel format`, you should consider how to break the content and any media into different card components to display within the carousel.
    * If requirements are underspecified, make reasonable assumptions to complete the design and functionality. 
    * Your goal is to deliver a working product with **no placeholder content** use actual values from Data Drift Analysis Report.
    * Ensure the generated code is valid and functional. Return only the code.
    * The output must be a complete and valid HTML document with no placeholder content for the developer to fill in.
    * Only return code, dont return any text like: `Here is the HTML document for the landing page based on the user's instructions: html`
    * If: data = "Agent invoke error: An error occurred (throttlingException) when calling the InvokeAgent operation: Your request rate is too high. Reduce the frequency of requests. Check your Bedrock model invocation quotas to find the acceptable frequency." show this error Else: show drift analysis reports

**Libraries:**
  Unless otherwise specified, use:
    * CSS
  Importance Dont use Javascript cause this html file can preview in email

Unless otherwise specified, use the following theme colors:

- primary color: #246db5
- secondary color: #5cadff
- background color: #ffffff
- text color: #1a1a1a
- primary text color: #ffffff


Data Drift Analysis Report:
```
{data}
```

"""

results = {
    "update_remediation": None,
    "remove_remediation": None,
    "query": None,
    "type": None
}

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def extract_repo_url(text: str):
    m = re.search(r"https?://github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+", text)
    return m.group(0) if m else None

def extract_detection(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "update_remediation":
                results["update_remediation"] = v
            elif k == "remove_remediation":
                results["remove_remediation"] = v
            elif k == "query":
                results["query"] = v
            elif k == "type":
                results["type"] = v
            else:
                extract_detection(v)
    elif isinstance(obj, list):
        for item in obj:
            extract_detection(item)

def finish_one_repo(repo_url):
    table.update_item(
        Key={"repoUrl": repo_url},
        UpdateExpression="SET scanStatus = :done, lastScanAt = :t, updatedAt = :t",
        ExpressionAttributeValues={":done": "DONE", ":t": now_utc()},
    )
    lambda_client.invoke(
        FunctionName=LAMBDA_NAME,
        InvocationType="Event",
        Payload=json.dumps({"eventName": "ScanNextRepo"})
    )
    return {"status": "completed", "repo": repo_url}

def lambda_handler(event, context):
    extract_detection(event)
    print("print event", event)
    
    update_remediation = results["update_remediation"]
    remove_remediation = results["remove_remediation"]
    logger.info(f"results: {results}")
    logger.info(f"update_remediation: {update_remediation}")
    logger.info(f"remove_remediation: {remove_remediation}")
    # Tạo date
    current_date = now_utc()#time.strftime('%Y%m%d')
    # Format prompt – chỉ dùng các key đã định nghĩa
    prompt_formatted = PROMPT.format(
        update_remediation=update_remediation,
        remove_remediation=remove_remediation,
        date=current_date
    )
    
    logger.info(f"Prompt for combined report: {prompt_formatted}...")
    
    agent_output = invoke_agent(prompt_formatted)
    logger.info(f"Agent raw output: {agent_output}...")
    
    parsed = extract_json_from_text(agent_output)
    repo_prefix = "cicd_log"
    query_type = results["type"]
    if query_type == "full_scan":
        query = results["query"].strip()
        repo_url = extract_repo_url(query)
        repo_prefix = repo_url.split("/")[-1]
        print(f"🔍 Query: {query}, Repo: {repo_url}")
        finish_one_repo(repo_url)
    
    if not parsed:
        parsed = "Agent invoke error: An error occurred (throttlingException) when calling the InvokeAgent operation: Your request rate is too high. Reduce the frequency of requests. Check your Bedrock model invocation quotas to find the acceptable frequency." 
    prompt_formatted = PROMPTT_GENERATE_HTML.format(
        data=parsed
    )
    repo_prefix = "cicd_log"
    logger.info(f"Gen HTML File: {prompt_formatted}...")
    html_content = invoke_agent(prompt_formatted)
    logger.info(f"Agent gen html_content raw output: {html_content}...")
    # === Save HTML to S3 ===
    bucket_name = "html-ai-gen"
    now_time = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    file_name = f"drift-{repo_prefix}-{now_time}.html"
    s3.put_object(
        Bucket=bucket_name,
        Key=file_name,
        Body=html_content.encode("utf-8"),
        ContentType="text/html",
        )
    # URL public (S3 static website endpoint)
    website_url = f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com/{file_name}"
    logger.info(f"✅ Uploaded to S3: {website_url}")
    return website_url

# === INVOKE AGENT ===
def invoke_agent(question: str, max_retries: int = 5):
    full_output = ""
    attempt = 0

    while attempt < max_retries:
        try:
            response = bedrock.invoke_agent(
                agentId=AGENT_ID,
                agentAliasId=AGENT_ALIAS_ID,
                sessionId=f"report-{int(time.time())}",
                inputText=question
            )

            for event in response.get("completion", []):
                chunk = event.get("chunk", {})
                bytes_data = chunk.get("bytes")
                if bytes_data:
                    full_output += bytes_data.decode("utf-8")

            # Nếu thành công, thoát khỏi vòng lặp retry
            return full_output

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            # Nếu là lỗi throttling thì backoff retry
            if error_code in ["ThrottlingException", "throttlingException"]:
                wait_time = (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning(
                    f"Rate limit hit. Retry {attempt + 1}/{max_retries} after {wait_time:.1f}s..."
                )
                time.sleep(wait_time)
                attempt += 1
                continue
            else:
                logger.error(f"Agent invoke error: {str(e)}")
                return f"Agent invoke error: {str(e)}"
        except Exception as e:
            logger.error(f"Agent invoke error: {str(e)}")
            return f"Agent invoke error: {str(e)}"

    # Nếu retry hết số lần mà vẫn lỗi throttling
    logger.error("Max retries reached due to throttling.")
    return "Agent invoke error: Max retries reached due to throttling."

# === EXTRACT JSON ===
def extract_json_from_text(text: str):
    try:
        print("=== [TRACE] START extract_json_from_text ===")
        full_text = text.strip()
        logger.info(f"[TRACE] Raw : {full_text}")

        # === B1: ƯU TIÊN TÌM JSON OBJECT { ... } ===
        start_obj = full_text.find('{')
        end_obj = full_text.rfind('}') + 1

        if start_obj != -1 and end_obj > start_obj:
            json_str = full_text[start_obj:end_obj]
            is_array = False
            print(f"[TRACE] Found JSON object: {len(json_str)} chars")
        else:
            # Nếu không có object, thử array
            start_arr = full_text.find('[')
            end_arr = full_text.rfind(']') + 1
            if start_arr != -1 and end_arr > start_arr:
                json_str = full_text[start_arr:end_arr]
                is_array = True
                print(f"[TRACE] Found JSON array: {len(json_str)} chars")
            else:
                print("[TRACE] No JSON found")
                return {}

        # === B2: Fix content bị cắt ===
        fixed = ""
        i = 0
        in_content = False

        while i < len(json_str):
            if not in_content and json_str[i:i+10] == '"content":':
                in_content = True
                fixed += json_str[i:i+10]
                i += 10
                quote = json_str.find('"', i)
                if quote == -1:
                    fixed += ' ""'
                    break
                fixed += json_str[i:quote+1]
                i = quote + 1
                continue

            if in_content and json_str[i] == '"' and json_str[i-1] != '\\':
                next_part = json_str[i+1:i+5]
                if any(x in next_part for x in [',', '}', '\n', '\r']):
                    in_content = False
            fixed += json_str[i]
            i += 1

        if in_content:
            fixed += '"INCOMPLETE"'

        json_str = fixed

        # === B3: Dọn phẩy thừa + đóng ngoặc ===
        json_str = re.sub(r',\s*([\]}])', r'\1', json_str)
        json_str = re.sub(r',\s*$', '', json_str)

        open_b = json_str.count('{')
        close_b = json_str.count('}')
        open_br = json_str.count('[')
        close_br = json_str.count(']')

        while open_b > close_b:
            json_str += '}'
            close_b += 1
        while open_br > close_br:
            json_str += ']'
            close_br += 1

        print(f"[TRACE] Final JSON: {json_str}")

        # === B4: Parse ===
        try:
            data = json.loads(json_str)
            return data
        except json.JSONDecodeError as e:
            print(f"[TRACE] JSON Error: {e}")
            print(f"[TRACE] JSON string:\n{json_str[:600]}")
            return {}  # Luôn trả object nếu là object

    except Exception as e:
        print(f"[TRACE] Exception: {e}")
        return {}
    finally:
        print("=== [TRACE] END extract_json_from_text ===")