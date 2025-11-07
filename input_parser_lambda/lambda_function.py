# ========================================
# input-parser-light.py — HỖ TRỢ 2 TYPE
# ========================================
import os
import json
import time
import logging
import boto3
import re
from botocore.config import Config

config = Config(
    retries={
        'max_attempts': 10,  # Default is 3
        'mode': 'adaptive'
    }
)

# === LOGGING CONFIG ===
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def log_info(obj):
    logger.info(json.dumps(obj, ensure_ascii=False))

# === CONFIG ===
REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "LBQSCKGFJM")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "DTC1TK3HZA")
bedrock = boto3.client("bedrock-agent-runtime", region_name=REGION, config=config)

# ========================================
def lambda_handler(event, context):
    start_time = time.time()
    query = event.get("query", "").strip()
    query_type = event.get("type", "full_scan")

    log_info({"step": "start", "type": query_type, "query_length": len(query)})

    if query_type == "cicd_log":
        result = parse_cicd_log(query)
    elif query_type == "full_scan":
        repo_url = extract_repo_url(query)
        if not repo_url:
            return {"error": "No repo_url found", "type": query_type}
        result = retrieve_iac_and_state(repo_url)
    else:
        return {"error": "Invalid type", "type": query_type}

    result["type"] = query_type
    result["latency_sec"] = round(time.time() - start_time, 3)
    log_info({"step": "completed", "result": result})
    return result


# ========================================
def parse_cicd_log(log_text: str):
    region= "us-east-1"
    prompt = f"""
SYSTEM INSTRUCTION:
You are an expert IaC drift analysis agent specialized in detecting infrastructure drift from Terraform CICD logs.
You analyze Terraform plan outputs and identify which resources were refreshed, changed, added, or destroyed.

KNOWLEDGE BASE DATA SOURCES:
All IaC configurations of the repository are stored under the directory `iac_config/` in the KB.

1. IaC Configurations (iac_config/)
Format: {{"resource_address": "resource.aws_instance.example", "type": "iac_configuration", "metadata": {{"repo": "..."}}}}
Search: Use query "iac_configuration resource_address"
Extract: resource_address field

2. AWS State (aws_state/{{region}}/)
Format: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}}}
Search: Use query "metadata.resourceType AWS resourceId"
Extract: Construct identifier from metadata.resourceType + (metadata.resourceName OR metadata.resourceId)
Filter: Exclude where metadata.status = "ResourceDeleted"

---

TASK:
Analyze the CICD_log content below and detect any drift, managed, or unmanaged resources.

Terraform_CICD_logs
```
{log_text}
```

OPERATIONAL RULES:
- Never ask for clarification.
- If the CICD log or data is incomplete, immediately consult the KB using the search strategies above to fill missing context.
- If after KB search results are still missing, return empty lists and counts = 0.
- You are fully autonomous; do not request user input under any condition.
- Always return a complete JSON response as described below.

ANALYSIS REQUIREMENTS:

1. **Extract all resources with "Refreshing state..."**
- Capture resource_address and AWS id (id=...).
- Convert each AWS id to an identifier using the mapping below.
- Count how many total resources were refreshed.

2. **Detect planned drift changes from Terraform plan section**
- Classify:
    - `~` → "update_in_place"
    - `+` → "add"
    - `-` → "destroy"
- Include drift details if available (e.g. “Ingress rule added: SSH from bastion”)

3. **Identify unmanaged resources**
- Any AWS resource that appears in “Refreshing state” but is **not found** in IaC configurations.
- You may simulate up to 3 KB searches per resource type.
- Add them under the “unmanaged” list with reason “Found in AWS but missing in IaC”.

4. **Return output strictly in JSON format** as shown below (no markdown, no explanation):

```json
{{
"cicd_drift": {{
    "total_refreshed": 28,
    "managed_count": 2,
    "drifted": [
    {{
        "resource_address": "module.security_groups.aws_security_group.app",
        "aws_identifier": "AWS__EC2__SecurityGroup_sg-02b7d03c53859c83b",
        "change_type": "update_in_place",
        "drift_details": "Ingress rule added: SSH from bastion"
    }},
    {{
        "resource_address": "module.security_groups.aws_security_group.web",
        "aws_identifier": "AWS__EC2__SecurityGroup_sg-071c0740b90741a4c",
        "change_type": "update_in_place",
        "drift_details": "Ingress rule added: SSH from bastion (if needed)"
    }}
    ],
    "unmanaged": [
    {{
        "aws_identifier": "AWS__EC2__SecurityGroup_sg-0ac94b35c49eced0b",
        "reason": "Found in AWS but missing in IaC"
    }}
    ]
}},
"summary": "28 refreshed, 2 drifted, 1 unmanaged"
}}
STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
"""
    return agent_query(prompt)



# ========================================
def retrieve_iac_and_state(repo_url: str):
    repo_prefix = repo_url.split("/")[-1]
    region = "us-east-1"
    prompt = f"""
TASK:
Compare IaC and AWS State resources for repository: {repo_url}, 

KNOWLEDGE BASE DATA SOURCES:
All IaC configurations of repo = {repo_url} are stored under the directory `iac_config/{repo_prefix}` in the KB.
1. IaC Configurations (iac_config/{repo_prefix}/)
Format: {{"resource_address": "resource.aws_instance.example", "type": "iac_configuration", "metadata": {{"repo": "..."}}}}
Search: Use query "iac_configuration {repo_url} resource_address"
Extract: resource_address field

2. AWS State (aws_state/{region}/)
Format: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}}}
Search: Use query "metadata.resourceType AWS resourceId"
Extract: Construct identifier from metadata.resourceType + (metadata.resourceName OR metadata.resourceId)
Filter: Exclude where metadata.status = "ResourceDeleted"

RESOURCE TYPE MAPPING:
- aws_instance ↔ AWS::EC2::Instance
- aws_s3_bucket ↔ AWS::S3::Bucket
- aws_security_group ↔ AWS::EC2::SecurityGroup
- aws_db_instance ↔ AWS::RDS::DBInstance
- aws_vpc ↔ AWS::EC2::VPC

SEARCH RULES:
1. Maximum 3 KB searches per request
2. Search #1: IaC resources → extract resource_address
3. Search #2: AWS state → construct identifier from metadata
4. If no results after 3 searches → return empty arrays
5. Count common = resources matching by type AND name

OUTPUT (mandatory JSON only):
{{
"repo_url": "{repo_prefix}",
"iac_resources": ["resource.aws_instance.example", ...],
"aws_state_resources": ["EC2Instance_web-server", ...],
"total_iac": <count>,
"total_state": <count>,
"summary": "{{total_iac}} IaC, {{total_state}} AWS. {{common}} common."
}}

STRICT RULES:
- Return valid JSON even if data missing (use empty arrays, 0 counts)
- Never ask clarification
- Never include explanations outside JSON
- Never search more than 3 times
- Resource addresses only - no content
"""
    return agent_query(prompt)


# ========================================
def extract_repo_url(text: str):
    m = re.search(r"https?://github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+", text)
    return m.group(0) if m else None


# ========================================
def agent_query(prompt: str):
    print("Invoking Bedrock Agent...")
    log_info(prompt)
    try:
        response = bedrock.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=f"parser-{int(time.time())}",
            inputText=prompt
        )
        
        full_output = ""
        seen = set()
        for event in response.get("completion", []):
            if "chunk" in event:
                chunk = event["chunk"]["bytes"].decode("utf-8")
                h = hash(chunk)
                if h not in seen:
                    seen.add(h)
                    full_output += chunk
        print("=== [TRACE] Full output ===", full_output)
        return extract_json_from_text(full_output)
        
    except Exception as e:
        log_info({"error": "Agent error", "detail": str(e)})
        return {"error": "Agent failed: "+ str(e)}


# ========================================
def extract_json_from_text(full_text: str):
    try:
        print("=== [TRACE] START extract_json_from_text ===", full_text)
        full_text = full_text.strip()
        print(f"[TRACE] Raw length: {len(full_text)}")

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
            if is_array:
                print(f"[TRACE] Parsed array: {len(data)} items")
                return data
            else:
                print(f"[TRACE] Parsed object: {list(data.keys())}")
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