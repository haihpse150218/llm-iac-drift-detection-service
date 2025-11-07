# lambda_function.py
import os
import json
import boto3
import logging
import time
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# === CONFIG ===
REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "LBQSCKGFJM")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "NTCPG9HUZF")
DETECTION_TYPE = os.environ.get("DETECTION_TYPE", "cross")

bedrock = boto3.client("bedrock-agent-runtime", region_name=REGION)

# === PROMPT DICTIONARY (DÁN PROMPTS BẠN CUNG CẤP) ===
PROMPTS = {
"normal": """
You are an expert in detecting Normal Drift (attribute differences).

KNOWLEDGE BASE RULES:
All IaC configurations of repo = {repo_url} are stored under the directory `iac_config/{repo_prefix}` in the KB.
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_url} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"
3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison for that IaC resource.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - If attribute differences exist, log them under `drifted_resources`.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Never rely on external assumptions or unstated data — only use content found in the Knowledge Base and provided inputs.
10. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1: forcus on infomation below, base on it and get details from KB
IaC Data (if any base on it and get details from KB else scan all KB): {iac_data} 
Desired State Data (if any base on it and get details from KB else scan from KB): {state_data}
CICD Drift Log (if any base on it and get details from KB else scan from KB): {cicd_drift}
2. Use the Knowledge Base according to the rules above.
3. Compare IaC vs AWS attributes (e.g., instance_type, AMI, subnet, etc.).
4. Document any detected drift.
5. Suggest remediation actions:
   - update_iac: Modify IaC files in `iac_config/` to resolve the drift.
   - remove_source: Rebuild or reset the source if needed.
6. Review all findings.
7. Compile a JSON report that includes only the top 50 high-risk drifts.

IMPORTANT: Start with JSON output only.
Output JSON:
{{
  "detection_type": "normal",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
""",
"policy": """
You are an expert in detecting Policy / Compliance Drift (valid but violating internal or AWS compliance rules).

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1: forcus on infomation below, base on it and get details from KB
IaC Data (if any base on it and get details from KB else scan all KB): {iac_data} 
Desired State Data (if any base on it and get details from KB else scan from KB): {state_data}
CICD Drift Log (if any base on it and get details from KB else scan from KB): {cicd_drift}
2. Use the Knowledge Base according to the rules above.
3. Identify any policy or compliance violations (e.g., open security group, missing tags, public access).
4. Document all drift with compliance context.
5. Suggest remediation actions:
   - update_iac: Fix IaC configurations in `iac_config/` to comply.
   - remove_source: Rebuild to remove non-compliant resources.
6. Review all findings.
7. Compile a JSON report that includes only the top 50 high-risk drifts.


IMPORTANT: Start with JSON output only.
Output JSON:
{{
  "detection_type": "policy",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs are missing.
- Only include up to 50 high-risk drifts.
- Never output explanations or commentary outside JSON.
- The output must be valid JSON following the schema.
""",
"semantic": """
You are an expert in detecting Semantic Drift (logical difference despite similar structure).

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
0: forcus on infomation below, base on it and get details from KB
IaC Data (if any base on it and get details from KB else scan all KB): {iac_data} 
Desired State Data (if any base on it and get details from KB else scan from KB): {state_data}
CICD Drift Log (if any base on it and get details from KB else scan from KB): {cicd_drift}
1. Use the Knowledge Base according to the rules.
2. Analyze semantic drift (same logic but different implementation, or vice versa).
3. Document drifts.
4. Suggest remediation:
   - update_iac: Modify IaC to match intended logic.
   - remove_source: Rebuild or refactor inconsistent semantics.
5. Review findings.
6. Compile a JSON report (top 50 high-risk drifts only).

Output JSON:
{{
  "detection_type": "semantic",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
""",

    "hidden": """
You are an expert in detecting Hidden / Implicit Configuration Drift.

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1. Use the Knowledge Base.
2. Identify hidden configurations (e.g., default SGs, auto-generated tags).
3. Document them.
4. Suggest remediation actions.
5. Compile a JSON report (top 50 high-risk drifts).

Output JSON:
{{
  "detection_type": "hidden",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
""",

    "cross": """
You are an expert in detecting Cross-Resource Dependency Drift.

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1. Use the Knowledge Base.
2. Identify cross-resource impacts.
3. Document dependencies and affected resources.
4. Suggest remediation.
5. Compile JSON report (top 50 high-risk drifts).

Output JSON:
{{
  "detection_type": "cross",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}
STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
""",

"behavioral": """
You are an expert in detecting Behavioral Drift.

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1. Use the Knowledge Base.
2. Detect runtime behavior differences (e.g., performance, downtime, cost).
3. Document behavioral drift.
4. Suggest remediation.
5. Compile JSON report (top 50 high-risk drifts).

OPERATIONAL RULES:
- Never ask for clarification.
- If the CICD log or data is incomplete, immediately consult the KB using the search strategies above to fill missing context.
- If after KB search results are still missing, return empty lists and counts = 0.
- You are fully autonomous; do not request user input under any condition.
- Always return a complete JSON response as described below.

Output JSON:
{{
  "detection_type": "behavioral",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
""",
"version": """
You are an expert in detecting Version / API-Level Drift.

KNOWLEDGE BASE RULES:
1. IaC Configs (iac_config/{repo_prefix}/)
   Structure: {{"resource_address": "resource.aws_instance.web", "type": "iac_configuration", "content": "...", "metadata": {{"repo": "{repo_url}"}}}}
   Search: "iac_configuration {repo_prefix} resource_address"
   Extract: resource_address, content (for attributes)

2. AWS State (aws_state/{region}/)
   Structure: {{"id": "AWS__EC2__Instance_i-123", "metadata": {{"resourceType": "AWS::EC2::Instance", "resourceId": "i-123", "resourceName": "web", "status": "ResourceDiscovered"}}, "configuration": {{"InstanceType": "t3.small", "ImageId": "ami-xyz"}}}}
   Search: "metadata.resourceType AWS configuration"
   Extract: metadata (type, id, name, status), configuration (attributes)
   Filter: Exclude status = "ResourceDeleted"

3. Always prioritize AWS Desired State configurations from the directory `aws_state/` in the Knowledge Base when comparing against IaC configurations.
4. All IaC configurations are located under `iac_config/{repo_prefix}/`, where `{repo_prefix}` corresponds to the current repo = {repo_url}.
5. For every IaC resource, find the corresponding AWS resource in the AWS Desired State:
   - Match by resource type, name, or ARN.
   - If no corresponding resource exists in AWS Desired State, skip comparison.
6. Do not invent or assume AWS resources that do not exist in the KB.
7. The Knowledge Base has already been synchronized and contains all available data in both directories: `iac_config/` and `aws_state/`.
8. Use the Knowledge Base to resolve drift detection as accurately as possible:
   - Retrieve and correlate related IaC and AWS resource blocks.
   - Prefer using data from AWS Desired State when conflict or uncertainty occurs.
9. Only include up to 50 high-risk drifts in the output (risk="high").

Step by Step:
1. Use the Knowledge Base.
2. Identify version mismatches or deprecated configs.
3. Document drifts.
4. Suggest remediation (update_iac / remove_source).
5. Compile JSON report (top 50 high-risk drifts).

Output JSON:
{{
  "detection_type": "version",
  "drifted_resources": [
    {{
      "resource_address": "...",
      "issue": "...",
      "risk": "high",
      "remediation_update_iac": "...",
      "remediation_remove_source": "..."
    }}
  ],
  "summary": "..."
}}

STRICT INSTRUCTION:
- Never ask clarification questions.
- Always proceed even if some inputs (iac_data, state_data, or cicd_drift) are missing or empty.
- Only include up to 50 high-risk drifts in the output.
- Never output explanations, reasoning, or commentary outside the JSON.
- The output must always be valid JSON following the specified schema.
"""
}
results = {
    "query": None,
    "type": None,
    "iac_resources": [],
    "aws_state_resources": [],
    "cicd_drift": {}
    
}
def extract_detection(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "query":
                results["query"] = v
            elif k == "type":
                results["type"] = v
            elif k == "iac_resources":
                results["iac_resources"] = v
            elif k == "aws_state_resources":
                results["aws_state_resources"] = v
            elif k == "cicd_drift":
                results["cicd_drift"] = v
            else:
                extract_detection(v)
    elif isinstance(obj, list):
        for item in obj:
            extract_detection(item)

def extract_repo_url(text: str):
    m = re.search(r"https?://github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+", text)
    return m.group(0) if m else None

# === MAIN HANDLER ===
def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)[:1000]}...")
    extract_detection(event)
    print("results: ", results)
    # Xác định loại xử lý
    type_ = results["type"]
    region="us-east-1"
    if type_ == "cicd_log":
        # 🟣 Trường hợp CICD log
        log_text = results["query"]
        if not log_text:
            logger.warning("Missing log_text for type=cicd_log")
            log_text = "(empty log)"
        iac_data = results["iac_resources"]
        state_data = results["aws_state_resources"]
        cicd_drift = results["cicd_drift"]
        prompt = PROMPTS[DETECTION_TYPE].format(
            repo_url="(N/A - CICD log)",
            iac_data="[]",
            state_data="[]",
            cicd_drift=cicd_drift,  # tránh log quá dài,
            repo_prefix="",
            region=region
        )

    else:
        # 🟢 Trường hợp full_scan (mặc định)
        repo_url = extract_repo_url(results["query"].strip())
        iac_data = results["iac_resources"]
        state_data = results["aws_state_resources"]
        cicd_drift = results["cicd_drift"]
        repo_prefix = repo_url.split("/")[-1]
        prompt = PROMPTS[DETECTION_TYPE].format(
            repo_url=repo_url,
            iac_data=iac_data,
            state_data=state_data,
            cicd_drift=cicd_drift,
            repo_prefix=repo_prefix,
            region=region
        )

    logger.info(f"Prompt for {DETECTION_TYPE}: {prompt}...")

    agent_output = invoke_agent(prompt)
    parsed = extract_json_from_text(agent_output)

    if parsed:
        parsed["detection_type"] = DETECTION_TYPE
        parsed["type"] = type_
        return parsed
    else:
        return {
            "detection_type": DETECTION_TYPE,
            "type": type_,
            "drifted_resources": [],
            "summary": "No drift detected or parsing failed"
        }

# === INVOKE AGENT ===
def invoke_agent(question: str):
    print("start invoke agent=========")
    full_output = ""
    try:
        response = bedrock.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=str(int(time.time())),
            inputText=question
        )
        print("response:", response)
        for event in response["completion"]:
            if "chunk" in event:
                full_output += event["chunk"]["bytes"].decode("utf-8")
        print(full_output)
    except Exception as e:
        logger.error(f"Agent invoke error: {str(e)}")
    return full_output

# === EXTRACT JSON ===
def extract_json_from_text(text: str):
    try:
        print("=== [TRACE] START extract_json_from_text ===")
        full_text = text.strip()
        print(f"[TRACE] Raw : {full_text}")

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